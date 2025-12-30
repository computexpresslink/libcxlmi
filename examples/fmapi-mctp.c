#include <sys/wait.h>
#include "examples.h"
#define MAX_CHARS 50
#define MAX_EXTENTS 10

enum {
    CREATE_DAX_DEVICE,
    LIST_DAX_DEVICE,
    ONLINE_DAX_DEVICE,
    LSMEM,
    NUM_CMDS
};

/* Hardcoded to use region0 and dax0.1 only. */
static char *DAX_DEVICE_CMDS[] = {
    [CREATE_DAX_DEVICE] = "daxctl create-device -r region0",
    [LIST_DAX_DEVICE] = "daxctl list -r region0 -D",
    [ONLINE_DAX_DEVICE] = "daxctl reconfigure-device dax0.1 -m system-ram",
    [LSMEM] = "lsmem"
};

/*
 * Prompts user for the number of extents they want to add/release with a max.
 * of 10. Prompts for each start/end DPA in MiB, keeping track of each one in
 * ext_list.
 * Returns the number of extents in ext_list. If user specifies invalid
 * start or end DPA, immediately returns number of valid extents previously
 * specified, if any.
 *
 * @param ext_list: used to fill out extent fields (length, start_dpa, etc.)
 * @param add: used to print "add" or "release" when prompting users
 * @returns: the number of extents user specified
 */
static int parse_extents(extent *ext_list, bool add)
{
    uint64_t num_extents;
    char input[MAX_CHARS];
    uint64_t start, end;
    char err = '\0';
    char *errp = &err;
    int i;

    memset(input, 0, MAX_CHARS);
    printf("How many extents to %s? (max. %d) ",
           add ? "add" : "release",
           MAX_EXTENTS);

    if (!fgets(input, MAX_CHARS, stdin)) {
        printf("Enter a valid number of extents.\n");
        return -1;
    }

    num_extents = strtol(input, NULL, 10);

    if (!num_extents || num_extents > 10) {
        printf("Enter a valid number of extents.\n");
        return -1;
    }

    if (!ext_list) {
        printf("Failed to allocate extent list\n");
        return -1;
    }

    for (i = 1; i <= num_extents; i++) {
        printf("Enter extent %d start-end in MB (ex: 0-128): ", i);

        if (!fgets(input, MAX_CHARS, stdin)) {
            printf("Invalid length.\n");
            return i - 1;
        }

        /* Parse extent string */
        char *split = strchr(input, '-');
        if (!split) {
            printf("Invalid length.\n");
            return i - 1;
        }
        *split = '\0';
        start = strtol(input, &errp, 10);
        /*
         * 0 is a valid start, so check *nptr is not '\0'
         * and **endptr is '\0' to ensure string was valid
         */
        if (*input == '\0' || err != '\0') {
            printf("Invalid extent start for extent %d.\n", i);
            return i - 1;
        }
        /* 0 is not a valid end so only need to check that end != 0*/
        end = strtol(split + 1, &errp, 10);
        if (!end) {
            printf("Invalid extent end for extent %d.\n", i);
            return i - 1;
        }

        if (end - start == 0) {
            printf("Start and end cannot be equal.\n");
            return i - 1;
        }

        start *= MiB;
        end *= MiB;

        ext_list[i - 1].start_dpa =  start;
        ext_list[i - 1].len = end - start;
    }

    return num_extents;
}

/*
 * Creates and sends 0x5604 FM Initiate DC Add to the given endpoint using
 * extents specified in ext_list.
 *
 * @param: num_extents - number of extents in ext_list
 * @param: ext_list - list of extents to include in add request
 * @param: ep - endpoint to send request through
 */
int send_add(int num_extents, extent *ext_list, struct cxlmi_endpoint *ep)
{
    struct cxlmi_cmd_fmapi_initiate_dc_add_req* add_req = NULL;
    int i, rc;
    uint64_t total_len = 0;

    add_req = calloc(1, sizeof(*add_req) +
                     num_extents * sizeof(add_req->extents[0]));

    if (!add_req) {
        free(ext_list);
        return -1;
    }

    add_req->host_id = 0;
    add_req->selection_policy = CXL_EXTENT_SELECTION_POLICY_PRESCRIPTIVE;
    add_req->ext_count = num_extents;

    for (i = 0; i < num_extents; i++) {
        add_req->extents[i].start_dpa = ext_list[i].start_dpa;
        add_req->extents[i].len = ext_list[i].len;
        total_len += ext_list[i].len;
    }

    add_req->length = total_len;
    printf("Sending add request for %i extents\n", num_extents);

    rc = cxlmi_cmd_fmapi_initiate_dc_add(ep, NULL, add_req);
    free(add_req);
    return rc;
}

/*
 * Creates and sends 0x5605 FM Initiate DC Release to the given endpoint using
 * extents specified in ext_list.
 *
 * @param: num_extents - number of extents in ext_list
 * @param: ext_list - list of extents to include in add request
 * @param: ep - endpoint to send request through
 */
int send_release(int num_extents, extent *ext_list, struct cxlmi_endpoint *ep)
{
    struct cxlmi_cmd_fmapi_initiate_dc_release_req* release_req = NULL;
    int i, rc;
    uint64_t total_len = 0;

    release_req = calloc(1, sizeof(*release_req) +
        num_extents * sizeof(release_req->extents[0]));

    if (!release_req) {
        free(ext_list);
        return -1;
    }

    release_req->host_id = 0;
    release_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
    release_req->ext_count = num_extents;

    for (i = 0; i < num_extents; i++) {
        release_req->extents[i].start_dpa = ext_list[i].start_dpa;
        release_req->extents[i].len = ext_list[i].len;
        total_len += ext_list[i].len;
    }

    release_req->length = total_len;
    printf("Sending release request for %i extents\n", num_extents);

    rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, release_req);

    free(release_req);
    return rc;
}

/*
 * Sends 0x5603 Get DC Region Extent Lists through the specified endpoint and
 * returns the number of extents on the device through the input pointer
 * num_extents. Prints extents info if parameter 'print' set to true
 *
 * @param: ep - endpoint to send request through
 * @param: print - if true, prints extent info
 * @returns: number of extents on the device or -1 if an error occurred
 */
static int get_extent_info(struct cxlmi_endpoint *ep, bool print)
{
    struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req;
    struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *rsp;
    int i, rc;

    req.host_id = 0;
    req.extent_count = MAX_EXTENTS;
    req.start_ext_index = 0;

    rsp = calloc(1, sizeof(*rsp) + req.extent_count * sizeof(rsp->extents[0]));

    if (!rsp) {
        return -1;
    }

    rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(ep, NULL, &req, rsp);
    if (rc) {
        rc = -1;
        goto free_out;
    }

    if (print) {
        printf("\tHost Id: %hu\n", rsp->host_id);
        printf("\tStarting Extent Index: %u\n", rsp->start_ext_index);
        printf("\tNumber of Extents Returned: %u\n", rsp->extents_returned);
        printf("\tTotal Extents: %u\n", rsp->total_extents);
        printf("\tExtent List Generation Number: %u\n",
               rsp->list_generation_num);

        for (i = 0; i < rsp->extents_returned; i++) {
            printf("\t\tExtent %d Info:\n", i);
            printf("\t\t\tStart DPA: 0x%08lx\n", rsp->extents[i].start_dpa);
            printf("\t\t\tLength: 0x%08lx\n", rsp->extents[i].len);
        }
    }
    rc = rsp->total_extents;

free_out:
    free(rsp);
    return rc;
}

/* Frees all endpoints for the given context and the context itself */
static void cleanup_ctx(struct cxlmi_ctx *ctx)
{
    struct cxlmi_endpoint *ep, *tmp;
    cxlmi_for_each_endpoint_safe(ctx, ep, tmp) {
        cxlmi_close(ep);
    }
    cxlmi_free_ctx(ctx);
}

/*
 * Splits input cmd into X tokens, using ' ' as the delimiter. Allocates space
 * for each token. Allocated space must be freed by the caller. Returns number
 * of tokens input cmd was split into.
 *
 * @param: cmd - a string to split using ' ' as the delimiter
 * @param: argv - null-terminated arr to store the tokens that cmd is split into
 * @returns: num tokens that cmd is split into (number of elements in argv - 1)
 */
static int split_cmd_to_argv(char* cmd, char*** argvp)
{
    char** argv;
    char* cmd_cpy = strdup(cmd);
    char* tok = strtok(cmd_cpy, " ");
    int i, argc = 0;

    while (tok != NULL) {
        tok = strtok(NULL, " ");
        argc++;
    }
    free(cmd_cpy);

    argv = calloc(argc + 1, sizeof(argv[0]));
    if (!argv) {
        printf("Failed to allocate argv\n");
        return -1;
    }

    cmd_cpy = strdup(cmd);
    tok = strtok(cmd_cpy, " ");
    argc = 0;
    while (tok != NULL) {
        argv[argc] = calloc(1, strlen(tok) + 1);

        if (!argv[argc]) {
            printf("Failed to allocate argv.\n");
            for (i = 0; i < argc; i++) {
                free(argv[argc]);
            }
            free(cmd_cpy);
            free(argv);
            return -1;
        }

        strcpy(argv[argc], tok);
        tok = strtok(NULL, " ");
        argc++;
    }

    argv[argc] = NULL;
    free(cmd_cpy);
    *argvp = argv;
    return argc;
}

/*
 * Parent proc forks and waits on child proc to execvp() the given file with
 * the given argv.
 *
 * @param: file - file for execvp()
 * @param: argv - arguments for execvp()
 * @param: rc - return code to store error info in
 */
static void execute_cmd(char* file, char** argv, int *rc)
{
    int pid = fork();

    if (pid < 0) {
        printf("Fork failed\n");
        exit(-1);
    }

    if (pid == 0) {
        if (execvp(file, argv)) {
            exit(-1);
        }
    } else {
        int status;
        wait(&status);
        if (!WIFEXITED(status)) {
            *rc = -1;
            return;
        }
        *rc = WEXITSTATUS(status);
    }
}

/*
 * Return true if user input == 'y'. Defaults to yes if nothing is entered.
 * False otherwise.
 * @param: buf - user input buf
 * @param: rc - pointer through which to return error codes
 */
static bool input_is_yes(char* buf, int *rc)
{
    if (!fgets(buf, MAX_CHARS, stdin)) {
        printf("Invalid input. Aborting\n");
        *rc = -1;
        return false;
    }

    return buf[0] == 'y' || buf[0] == '\n';
}

/*
 * Prompts user to create DAX device. Defaults to 'y' if nothing entered.
 * If 'y', create and online a DAX Device by executing the commands defined in
 * DAX_DEVICE_CMDS.
 * The commands are parsed into an argv and executed by a child proc via
 * fork() and exec().
 *
 * @return: -1 if executing a command failed. 0 otherwise.
 */
static int create_dax_device(void) {
    char buf[MAX_CHARS] = {0};
    char** argv = NULL;
    int i, j, rc = 0, argc;

    printf("Create DAX Device for this region? [y/n] ");
    if (input_is_yes(buf, &rc)) {
        for (i = 0; i < NUM_CMDS; i++) {
            memset(buf, 0, MAX_CHARS);
            argv = NULL;
            printf("%s\n", DAX_DEVICE_CMDS[i]);

            argc = split_cmd_to_argv(DAX_DEVICE_CMDS[i], &argv);

            if (argc < 0) {
                printf("Failed to split command\n");
                return -1;
            }

            execute_cmd(argv[0], argv, &rc);

            for (j = 0; j < argc; j++) {
                free(argv[j]);
            }
            free(argv);

            if (rc) {
                return rc;
            }

            if (i < NUM_CMDS - 1) {
                printf("Next cmd: '%s' ------------- continue? [y/n] ",
                       DAX_DEVICE_CMDS[i + 1]);
                if (!input_is_yes(buf, &rc)) {
                    break;
                }
            }
        }
    } else {
        printf("Skipping DAX Device creation for this region.\n");
    }
    return rc;
}

int main(int argc, char **argv)
{
    struct cxlmi_ctx *ctx;
    struct cxlmi_endpoint *ep, *tmp;
    extent *ext_list;
    char buf[MAX_CHARS];
    uint8_t cmd;
    int rc = 0, num_extents;

    ext_list = calloc(MAX_EXTENTS, sizeof(extent));
    if (!ext_list) {
        fprintf(stderr, "cannot allocate extent list\n");
        return EXIT_FAILURE;
    }

    ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
    if (!ctx) {
        fprintf(stderr, "cannot create new context object\n");
        free(ext_list);
        return EXIT_FAILURE;
    }

    if (argc == 1) {
        int num_ep = cxlmi_scan_mctp(ctx);

        printf("scanning dbus...\n");

        if (num_ep < 0) {
            fprintf(stderr, "dbus scan error\n");
            rc = -1;
            goto exit_free_ctx;
        } else if (num_ep == 0) {
            printf("no endpoints found\n");
            rc = -1;
            goto exit_free_ctx;
        } else
            printf("found %d endpoint(s)\n", num_ep);
    } else if (argc == 3) {
        unsigned int nid;
        uint8_t eid;

        nid = strtol(argv[1], NULL, 10);
        eid = strtol(argv[2], NULL, 10);
        printf("ep %d:%d\n", nid, eid);

        ep = cxlmi_open_mctp(ctx, nid, eid);
        if (!ep) {
            fprintf(stderr, "cannot open MCTP endpoint %d:%d\n", nid, eid);
            rc = -1;
            goto exit_free_ctx;
        }
    } else {
        fprintf(stderr, "must provide MCTP endpoint nid:eid tuple\n");
        rc = -1;
        goto exit_free_ctx;
    }

    cxlmi_for_each_endpoint_safe(ctx, ep, tmp) {
        if (ep_supports_op(ep, 0x5600)) {
            while (true) {
                memset(buf, 0, MAX_CHARS);
                memset(ext_list, 0, sizeof(extent) * MAX_EXTENTS);
                printf("Enter 1 (add), 2 (release), 3 (print). Otherwise, exit: ");
                if (!fgets(buf, MAX_CHARS, stdin)) {
                    goto create_dax_device;
                }
                cmd = strtol(buf, NULL, 10);
                if (!cmd) {
                    goto create_dax_device;
                }

                switch (cmd) {
                    case 1:
                        num_extents = parse_extents(ext_list, 1);
                        if (num_extents > 0) {
                            rc = send_add(num_extents, ext_list, ep);
                        }
                        break;
                    case 2:
                        num_extents = parse_extents(ext_list, 0);
                        if (num_extents > 0) {
                            rc = send_release(num_extents, ext_list, ep);
                        }
                        break;
                    case 3:
                        rc = get_extent_info(ep, true);
                        break;
                }

            }
        }
        cxlmi_close(ep);
    }
create_dax_device:
    /* Create DAX Device if extents were added */
    if (get_extent_info(ep, false) > 0) {
        rc = create_dax_device();
    }
exit_free_ctx:
    free(ext_list);
    cleanup_ctx(ctx);
    return rc;
}