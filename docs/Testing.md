# Mock Device Testing Infrastructure

libcxlmi includes a mock transport layer that enables comprehensive testing without
requiring physical CXL hardware. This document explains the architecture, benefits,
limitations, and usage of the mock testing infrastructure.

## Overview

The mock transport simulates a CXL device endpoint, allowing test code to:

- Send CXL-MI commands through the library's normal API
- Configure expected responses with specific return codes and payloads
- Verify that commands are properly formatted before transmission
- Test error handling paths that are difficult to trigger with real hardware

This enables developers to validate library behavior, catch regressions, and verify
protocol correctness without access to CXL devices.

## Architecture

### How It Works

The mock transport intercepts commands at the transport layer, where the library
would normally send data over MCTP or through a mailbox interface:

```
┌─────────────────┐
│   Test Code     │
└────────┬────────┘
         │ cxlmi_cmd_*()
         ▼
┌─────────────────┐
│  libcxlmi API   │
│  (commands.c)   │
└────────┬────────┘
         │ send_cmd_cci()
         ▼
┌─────────────────┐
│ Mock Transport  │  ← Intercepts here instead of real hardware
│   (mock.c)      │
└─────────────────┘
```

When a command is sent to a mock endpoint:

1. The library builds the CCI message (command set, opcode, payload) exactly as
   it would for real hardware
2. The mock transport records the command for later verification
3. It looks up a pre-configured response matching the command set and opcode
4. It returns that response (or "unsupported" if none was configured)
5. The library processes the response and returns to the caller

This means the entire command encoding/decoding path is exercised, just as it
would be with a real device.

### Key Components

**`src/cxlmi/mock.c`** - Mock transport implementation:
- `cxlmi_open_mock()` - Creates a mock endpoint
- `cxlmi_mock_set_response()` - Queues a response for a specific command
- `cxlmi_mock_get_last_command()` - Retrieves the last command sent (for verification)
- `cxlmi_mock_get_stats()` - Returns command/response counts
- `send_mock_cmd()` - Internal function that handles mock command processing

**`src/cxlmi/test.h`** - Public test API header (separate from `libcxlmi.h` to
keep the main API clean)

**`tests/mock-tests.c`** - Comprehensive test suite using the mock infrastructure

## Benefits

### Hardware Independence

The primary benefit is the ability to test without CXL hardware. This enables:

- CI/CD pipelines that run on standard servers
- Development on laptops and workstations
- Testing of commands for devices that don't exist yet

### Complete Path Coverage

Unlike unit tests that mock at the function level, the mock transport exercises
the complete command path:

- Struct serialization to wire format
- Endianness conversion (host byte order ↔ little-endian wire format)
- Payload size calculations
- Response parsing and field extraction

### Error Path Testing

Real hardware rarely returns errors, making error handling difficult to test.
The mock transport can simulate any return code:

```c
/* Test handling of background operation status */
cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_BACKGROUND, NULL, 0);
rc = cxlmi_cmd_identify(ep, NULL, &id);
assert(rc == CXLMI_RET_BACKGROUND);
```

### Protocol Verification

Tests can verify that commands are encoded correctly by inspecting the raw
payload sent to the mock transport:

```c
/* Verify 64-bit field is encoded as little-endian */
cxlmi_mock_get_last_command(ep, &cmd_set, &cmd, payload, &payload_size);
assert(payload[0] == 0x78);  /* Low byte of 0x12345678 */
assert(payload[3] == 0x12);  /* High byte */
```

### Regression Testing

With 299 tests covering various commands, return codes, and edge cases, the
test suite catches regressions when modifying the library.

## Limitations

### No Device Logic

The mock transport does not simulate device behavior. It simply returns
pre-configured responses. This means:

- It cannot validate that a request makes sense for the device state
- It cannot simulate stateful operations (e.g., firmware update progress)
- It cannot test timing-dependent behavior

### Response Configuration Required

Every command needs a response configured before it's sent. Unconfigured
commands return `CXLMI_RET_UNSUPPORTED`. This is intentional—it forces tests
to be explicit about expected behavior.

### Single Response Per Command

Responses are consumed in FIFO order per command. For commands that might be
called multiple times, you must queue multiple responses:

```c
/* Queue 3 responses for retry testing */
cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_BUSY, NULL, 0);
cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_BUSY, NULL, 0);
cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
```

### No MCTP/Transport Layer Testing

The mock transport bypasses the actual transport layer (MCTP, mailbox). To test
transport-level behavior, you need real hardware or a separate transport mock.

## Usage

### Basic Test Pattern

```c
#include <libcxlmi.h>
#include <cxlmi/test.h>

void test_identify(void)
{
    struct cxlmi_ctx *ctx;
    struct cxlmi_endpoint *ep;
    struct cxlmi_cmd_identify_rsp wire_rsp = {0};
    struct cxlmi_cmd_identify_rsp result;
    int rc;

    /* Create context and mock endpoint */
    ctx = cxlmi_new_ctx(stderr, LOG_ERR);
    ep = cxlmi_open_mock(ctx);

    /* Configure the response the mock should return */
    wire_rsp.vendor_id = cpu_to_le16(0x1234);
    wire_rsp.device_id = cpu_to_le16(0x5678);
    cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_SUCCESS,
                            &wire_rsp, sizeof(wire_rsp));

    /* Call the library function under test */
    rc = cxlmi_cmd_identify(ep, NULL, &result);

    /* Verify results */
    assert(rc == CXLMI_RET_SUCCESS);
    assert(result.vendor_id == 0x1234);
    assert(result.device_id == 0x5678);

    /* Cleanup */
    cxlmi_close(ep);
    cxlmi_free_ctx(ctx);
}
```

### Testing Request Encoding

To verify that a request is encoded correctly on the wire:

```c
void test_request_encoding(void)
{
    struct cxlmi_cmd_set_timestamp_req req = {0};
    uint8_t cmd_set, cmd;
    uint8_t payload[64];
    size_t payload_size = sizeof(payload);

    /* ... setup mock endpoint ... */

    req.timestamp = 0x0102030405060708ULL;

    cxlmi_mock_set_response(ep, 0x03, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
    cxlmi_cmd_set_timestamp(ep, NULL, &req);

    /* Retrieve and verify the raw command payload */
    cxlmi_mock_get_last_command(ep, &cmd_set, &cmd, payload, &payload_size);

    assert(cmd_set == 0x03);  /* TIMESTAMP command set */
    assert(cmd == 0x01);      /* SET_TIMESTAMP opcode */

    /* Verify little-endian encoding */
    assert(payload[0] == 0x08);  /* LSB */
    assert(payload[7] == 0x01);  /* MSB */
}
```

### Testing Error Handling

```c
void test_error_handling(void)
{
    struct cxlmi_cmd_identify_rsp id;
    int rc;

    /* ... setup mock endpoint ... */

    /* Configure mock to return an error */
    cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_INVALID_INPUT, NULL, 0);

    rc = cxlmi_cmd_identify(ep, NULL, &id);

    assert(rc == CXLMI_RET_INVALID_INPUT);
}
```

## Test Categories

The test suite (`tests/mock-tests.c`) covers several categories:

| Category | Description |
|----------|-------------|
| Mock Infrastructure | Tests for the mock transport itself |
| Generic Component Commands | Identify, background operation status |
| Events Commands | Get/clear event records |
| Firmware Update Commands | Get FW info, transfer, activate |
| Timestamp Commands | Get/set timestamp |
| Logs Commands | Get log, supported logs, CEL |
| Features Commands | Get/set features |
| Memory Device Commands | Sanitize, secure erase |
| Health Info/Alerts Commands | Health info, alert config |
| Media and Poison Commands | Poison list, inject/clear poison |
| DCD Config Commands | Dynamic capacity configuration |
| FM-API Commands | Fabric Manager API commands |
| Error Code Handling | All CXL return codes |
| Request Payload Verification | Wire format encoding |
| Response Payload Verification | Wire format decoding |
| Endianness Verification | Multi-byte field byte order |

## Running Tests

Build and run the test suite:

```bash
meson setup build
meson compile -C build
./build/tests/mock-tests
```

Example output:

```
Mock Infrastructure:
  test_mock_create_close                                       [PASS]
  test_mock_no_response_returns_unsupported                    [PASS]
  test_mock_stats_tracking                                     [PASS]
  ...

==========================================================
Results: 299 passed, 0 failed, 299 total
==========================================================
```

## Code Coverage

The project supports code coverage reporting using gcov/lcov. This helps identify
untested code paths and measure test effectiveness.

### Prerequisites

Install the coverage tools:

```bash
# Debian/Ubuntu
apt install lcov

# Fedora/RHEL
dnf install lcov

# Or use gcovr instead
pip install gcovr
```

### Generating Coverage Reports

1. **Configure a coverage build:**

```bash
meson setup build-coverage -Db_coverage=true
```

2. **Build and run tests:**

```bash
meson compile -C build-coverage
meson test -C build-coverage
```

3. **Generate reports:**

```bash
# HTML report (recommended for detailed analysis)
ninja -C build-coverage coverage-html
# Opens: build-coverage/meson-logs/coveragereport/index.html

# Text summary
ninja -C build-coverage coverage-text

# XML report (for CI integration)
ninja -C build-coverage coverage-xml

# Sonarqube format
ninja -C build-coverage coverage-sonarqube
```

### Understanding Coverage Output

The coverage report shows three metrics:

- **Line coverage**: Percentage of executable lines that were run
- **Function coverage**: Percentage of functions that were called
- **Branch coverage**: Percentage of conditional branches taken

Example output:
```
Summary coverage rate:
  lines......: 77.9% (7681 of 9863 lines)
  functions..: 82.2% (416 of 506 functions)
  branches...: 47.9% (2138 of 4459 branches)
```

### HTML Report Navigation

The HTML report provides:

- **Directory view**: Coverage breakdown by directory
- **File view**: Line-by-line coverage highlighting
  - Green: Executed lines
  - Red: Unexecuted lines
  - Yellow: Partially covered branches
- **Summary statistics**: Overall and per-file metrics

### CI Integration

For continuous integration, use the text or XML output:

```bash
# Get a quick pass/fail based on coverage threshold
ninja -C build-coverage coverage-text 2>&1 | grep "lines"

# Generate Cobertura XML for CI tools (Jenkins, GitLab, etc.)
ninja -C build-coverage coverage-xml
# Output: build-coverage/meson-logs/coverage.xml
```

### Improving Coverage

When coverage reports show gaps:

1. **Identify uncovered functions**: Look for red functions in the HTML report
2. **Add targeted tests**: Create tests that exercise the uncovered paths
3. **Consider error paths**: Many gaps are in error handling code
4. **Check branch coverage**: Ensure both true/false paths are tested

Example of adding a test for an uncovered error path:

```c
static int test_error_resource_exhausted(void)
{
    struct cxlmi_cmd_identify_rsp id;
    int rc;

    ASSERT_EQ(setup(), 0, "setup failed");
    cxlmi_mock_set_response(test_ep, 0x00, 0x01,
                            CXLMI_RET_RESOURCES_EXHAUSTED, NULL, 0);
    rc = cxlmi_cmd_identify(test_ep, NULL, &id);
    teardown();

    ASSERT_EQ(rc, CXLMI_RET_RESOURCES_EXHAUSTED, "wrong error code");
    return 0;
}
```

## Adding New Tests

When adding support for a new command, add corresponding tests:

1. **Basic functionality test** - Configure a valid response and verify the
   library returns correct values

2. **Request encoding test** - Verify multi-byte fields are encoded as
   little-endian on the wire

3. **Response decoding test** - Provide a little-endian wire response and
   verify fields are converted to host byte order

4. **Error handling test** - Verify the command handles error return codes

See existing tests in `tests/mock-tests.c` for examples.
