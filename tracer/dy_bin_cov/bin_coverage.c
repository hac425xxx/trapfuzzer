#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drx.h"
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#else
#include <Windows.h>
#include <string.h>
#define strcasecmp _stricmp
#endif

#ifdef DEBUG
#define ASSERT(x, msg) DR_ASSERT_MSG(x, msg)
#define IF_DEBUG(x) x
#else
#define ASSERT(x, msg) /* nothing */
#define IF_DEBUG(x)    /* nothing */
#endif

/* XXX: should be moved to DR API headers? */
#define BUFFER_SIZE_BYTES(buf) sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf) (BUFFER_SIZE_BYTES(buf) / sizeof((buf)[0]))
#define BUFFER_LAST_ELEMENT(buf) (buf)[BUFFER_SIZE_ELEMENTS(buf) - 1]
#define NULL_TERMINATE_BUFFER(buf) BUFFER_LAST_ELEMENT(buf) = 0
#define ALIGNED(x, alignment) ((((ptr_uint_t)x) & ((alignment)-1)) == 0)
#define TESTANY(mask, var) (((mask) & (var)) != 0)
#define TEST TESTANY

#ifdef WINDOWS
#define IF_WINDOWS(x) x
#define IF_UNIX_ELSE(x, y) y
#else
#define IF_WINDOWS(x)
#define IF_UNIX_ELSE(x, y) x
#endif

/* Checks for both debug and release builds: */
#define USAGE_CHECK(x, msg) DR_ASSERT_MSG(x, msg)

typedef struct _COV_MODULE_INFO
{
    char module_name[0x100];
    unsigned char module_id;
    size_t image_start;
    size_t image_end;
    struct _COV_MODULE_INFO *next;
} COV_MODULE_INFO;

unsigned int g_cov_mod_count = 0;

typedef struct _OPTION_INFO
{
    unsigned int debug_mode;
    char trace_output_path[0x200];
    char log_path[0x200];
    file_t log_file;
	file_t trace_file;
} OPTION_INFO;

typedef struct _BB_ITEM
{
    unsigned int mod_id;
    unsigned int mod_rva;
} BB_ITEM;

OPTION_INFO g_option = {0};

COV_MODULE_INFO *g_cov_mod_list = NULL;

int log_bb(BB_ITEM *bi)
{
    if (g_option.trace_file == INVALID_FILE)
    {
		dr_fprintf(g_option.log_file, "0x%x,", bi->mod_rva);
        return 0;
    }

	dr_write_file(g_option.trace_file, bi, sizeof(BB_ITEM));


    return 0;
}

void add_cov_mod_info(char *module_name)
{
    COV_MODULE_INFO *info = (COV_MODULE_INFO *)malloc(sizeof(COV_MODULE_INFO));
    memset(info, 0, sizeof(COV_MODULE_INFO));

    strncpy(info->module_name, module_name, sizeof(info->module_name));

    info->module_id = g_cov_mod_count++;

    if (g_cov_mod_list == NULL)
    {
        g_cov_mod_list = info;
    }
    else
    {
        info->next = g_cov_mod_list->next;
        g_cov_mod_list->next = info;
    }

    if (g_option.debug_mode)
    {
		dr_fprintf(g_option.log_file, "add cov mod: %s, id:%d\n", info->module_name, info->module_id);
    }
}

COV_MODULE_INFO *find_cov_mod_by_pc(size_t pc)
{

    COV_MODULE_INFO *cov_info = g_cov_mod_list;
    while (cov_info)
    {
        if (pc >= cov_info->image_start && pc <= cov_info->image_end)
        {
            return cov_info;
        }
        cov_info = cov_info->next;
    }
    return NULL;
}

void destory_client()
{
    if (g_option.trace_file != INVALID_FILE)
    {
        dr_close_file(g_option.trace_file);
    }

    BB_ITEM bi = {0};
    FILE *fp = fopen(g_option.trace_output_path, "rb");
    while (fread(&bi, sizeof(BB_ITEM), 1, fp) == 1)
    {
		dr_fprintf(g_option.log_file, "%d!0x%x\n", bi.mod_id, bi.mod_rva);
    }
    fclose(fp);
}

static void
event_exit(void)
{

    FILE *fp = fopen("dy.status", "w");

    fprintf(fp, "normal\n");
    fclose(fp);
    destory_client();
    drx_exit();
    drmgr_exit();
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{

    drmgr_disable_auto_predication(drcontext, bb);
    if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;
    size_t pc = (size_t)dr_fragment_app_pc(tag);

    COV_MODULE_INFO *cov_info = find_cov_mod_by_pc(pc);

    if (cov_info == NULL)
        return DR_EMIT_DEFAULT;

    BB_ITEM bi;
    bi.mod_id = cov_info->module_id;
    bi.mod_rva = (unsigned int)pc - cov_info->image_start;

    log_bb(&bi);
    return DR_EMIT_DEFAULT;
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    const char *module_name = dr_module_preferred_name(info);

    if (g_option.debug_mode)
		dr_fprintf(g_option.log_file, "module %s loaded\n", module_name);

    COV_MODULE_INFO *cov_info = g_cov_mod_list;

    while (cov_info)
    {
        if (strcmp(cov_info->module_name, module_name) == 0)
        {
            cov_info->image_start = (size_t)info->start;
            cov_info->image_end = (size_t)info->end;
            if (g_option.debug_mode)
				dr_fprintf(g_option.log_file, "%s:%z\n", module_name, cov_info->image_start);
            break;
        }

        cov_info = cov_info->next;
    }
}

#if _WIN32

static bool
onexception(void *drcontext, dr_exception_t *excpt)
{
    DWORD exception_code = excpt->record->ExceptionCode;

    if (g_option.debug_mode)
		dr_fprintf(g_option.log_file, "Exception caught: %x\n", exception_code);

    if ((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
        (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
        (exception_code == EXCEPTION_PRIV_INSTRUCTION) ||
        (exception_code == EXCEPTION_INT_DIVIDE_BY_ZERO) ||
        (exception_code == STATUS_HEAP_CORRUPTION) ||
        (exception_code == EXCEPTION_STACK_OVERFLOW) ||
        (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
        (exception_code == STATUS_FATAL_APP_EXIT))
    {
        if (g_option.debug_mode)
        {
            dr_fprintf(g_option.log_file, "crashed\n");
        }

        dr_exit_process(1);
    }
    return true;
}
#else
dr_signal_action_t
onexception(void *drcontext, dr_siginfo_t *siginfo)
{
    if (siginfo->sig == SIGILL ||
        siginfo->sig == SIGBUS ||
        siginfo->sig == SIGFPE ||
        siginfo->sig == SIGSEGV ||
        siginfo->sig == SIGABRT)
    {
        destory_client();
        dr_printf("catch sig: %d\n", siginfo->sig);

        FILE *fp = fopen("dy.status", "w");

        fprintf(fp, "crash\n");
        fclose(fp);

        fp = fopen("dy.crash", "w");
        fprintf(fp, "catch sig: %d\n", siginfo->sig);
        fclose(fp);

        dr_abort();
    }

    return DR_SIGNAL_DELIVER; //return normal
}
#endif

void help_menu()
{
    dr_fprintf(STDERR, "\nHelp menu\n");
    dr_fprintf(STDERR, "    drrun -c libbincov.so [option] -- <your program> <program args>\n");
    dr_fprintf(STDERR, "    option:\n");
    dr_fprintf(STDERR, "    -coverage_module module_name\n");
    dr_fprintf(STDERR, "    -trae_output path\n");
}

static void
options_init(client_id_t id, int argc, const char *argv[])
{
    int i;
    const char *token;

	g_option.trace_file = INVALID_FILE;
    strncpy(g_option.log_path, "bin-cov-log.txt", sizeof(g_option.log_path));
	
    g_option.log_file = dr_open_file(g_option.log_path, DR_FILE_WRITE_OVERWRITE);

    for (i = 1 /*skip client*/; i < argc; i++)
    {
        token = argv[i];
        if (strcmp(token, "-coverage_module") == 0)
        {
            USAGE_CHECK((i + 1) < argc, "missing module");
            add_cov_mod_info((char *)argv[++i]);
        }
        else if (strcmp(token, "-debug") == 0)
        {
            g_option.debug_mode = 1;
        }
        else if (strcmp(token, "-trace_output") == 0)
        {
            USAGE_CHECK((i + 1) < argc, "missing output path");
            char *fpath = (char *)argv[++i];
            g_option.trace_file = dr_open_file(fpath, DR_FILE_WRITE_OVERWRITE);

            if (g_option.trace_file == INVALID_FILE)
            {
                dr_fprintf(STDERR, "open %s failed\n", fpath);
                dr_abort();
            }
            strncpy(g_option.trace_output_path, fpath, sizeof(g_option.trace_output_path));
        }
        else
        {

            dr_printf("UNRECOGNIZED OPTION: \"%s\"\n", token);
            help_menu();
            USAGE_CHECK(false, "invalid option");
        }
    }
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("dycov", "https://www.cnblogs.com/hac425");
    if (!drmgr_init() || !drx_init())
        DR_ASSERT(false);

    dr_fprintf(STDERR, "dr_client_main.\n");

    if (argc < 2)
    {
        dr_printf("libbincov.so coverage_module\n");
        dr_abort();
    }

    options_init(id, argc, argv);

#if _WIN32
    drmgr_register_exception_event(onexception);
#else
    drmgr_register_signal_event(onexception);
#endif

    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(event_module_load);
    if (!drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL))
        DR_ASSERT(false);
}
