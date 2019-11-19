#define PLUGIN_IMPLEMENT 1
#include <sys/wait.h>
#include <antd/plugin.h>
#include "antd/ini.h"
dictionary cgi_bin = NULL;

static int ini_handle(void *user_data, const char *section, const char *name,
                      const char *value)
{
    UNUSED(user_data);
    if (EQU(section, "CGI"))
    {
        dput(cgi_bin, name, strdup(value));
        LOG("put %s for %s\n", value, name);
    }
    else
    {
        return 0;
    }
    return 1;
}

void init()
{
    use_raw_body();
    cgi_bin = dict();
    char *cnf = config_dir();
    char *file = __s("%s/cgi.ini", cnf);
    // read ini file
    if (ini_parse(file, ini_handle, NULL) < 0)
    {
        LOG("Can't load '%s'\n", file);
    }
    else
    {
        LOG("CGI config loaded\n");
    }
    free(cnf);
    free(file);
}
void destroy()
{
    if (cgi_bin)
        freedict(cgi_bin);
}

static void add_vars(list *l, char *k, char *v)
{
    if (!v || !l || !k)
        return;
    char *data = __s("%s=%s", k, v);
    list_put_s(l, data);
    free(data);
}

static void write_request_body(antd_request_t *rq, int fd)
{
    char *tmp = (char *)dvalue(rq->request, "METHOD");
    if (!tmp || EQU(tmp, "GET") || EQU(tmp, "HEAD"))
        return;
    int clen = -1;
    dictionary header = (dictionary)dvalue(rq->request, "REQUEST_HEADER");
    tmp = (char *)dvalue(header, "Content-Length");
    if (tmp)
        clen = atoi(tmp);
    if (clen == -1)
        return;
    // read data and write to the fd
    char buf[BUFFLEN];
    int readlen = clen > BUFFLEN ? BUFFLEN : clen;
    int read = 0, stat = 1;
    while (readlen > 0 && stat > 0)
    {
        stat = antd_recv(rq->client, buf, readlen);
        if (stat > 0)
        {
            read += stat;
            readlen = (clen - read) > BUFFLEN ? BUFFLEN : (clen - read);
            write(fd, buf, stat);
        }
    }
}
static char *get_cgi_bin(antd_request_t *rq)
{
    char *tmp = (char *)dvalue(rq->request, "RESOURCE_PATH");
    if (!tmp)
        return NULL;
    tmp = ext(tmp);
    if (!tmp)
        return NULL;
    char *bin = (char *)dvalue(cgi_bin, tmp);
    LOG("CGI  CMD: %s\n", bin);
    free(tmp);
    return bin;
}
static list get_env_vars(antd_request_t *rq)
{
    char *tmp = NULL;
    char *sub = NULL;
    plugin_header_t *__plugin__ = meta();
    dictionary request = (dictionary)rq->request;
    dictionary header = (dictionary)dvalue(rq->request, "REQUEST_HEADER");
    list env_vars = list_init();
    add_vars(&env_vars, "GATEWAY_INTERFACE", "CGI/1.1");
    add_vars(&env_vars, "SERVER_SOFTWARE", SERVER_NAME);
    tmp = (char *)dvalue(request, "REQUEST_QUERY");
    if (!tmp)
        add_vars(&env_vars, "QUERY_STRING", "");
    else
    {
        sub = strchr(tmp, '?');
        if (sub)
        {
            sub++;
            add_vars(&env_vars, "QUERY_STRING", sub);
        }
        else
            add_vars(&env_vars, "QUERY_STRING", "");
    }
    tmp = (char *)dvalue(request, "METHOD");
    if (tmp)
        add_vars(&env_vars, "REQUEST_METHOD", tmp);
    tmp = (char *)dvalue(header, "Content-Type");
    if (tmp)
        add_vars(&env_vars, "CONTENT_TYPE", tmp);
    else
        add_vars(&env_vars, "CONTENT_TYPE", "");
    tmp = (char *)dvalue(header, "Content-Length");
    if (tmp)
        add_vars(&env_vars, "CONTENT_LENGTH", tmp);
    else
        add_vars(&env_vars, "CONTENT_LENGTH", "");
    add_vars(&env_vars, "DOCUMENT_ROOT", __plugin__->htdocs);
    tmp = (char *)dvalue(request, "REQUEST_PATH");
    if (tmp)
        add_vars(&env_vars, "PATH_INFO", tmp);
    else
        add_vars(&env_vars, "PATH_INFO", "");
    tmp = (char *)dvalue(header, "REMOTE_ADDR");
    add_vars(&env_vars, "REMOTE_ADDR", tmp);
    add_vars(&env_vars, "REMOTE_HOST", tmp);
    add_vars(&env_vars, "SERVER_NAME", SERVER_NAME);
    add_vars(&env_vars, "SERVER_PORT", (char *)dvalue(header, "SERVER_PORT"));
    add_vars(&env_vars, "SERVER_PROTOCOL", "HTTP/1.1");
    // add remaining header to the vars
    association it;
    for_each_assoc(it, header)
    {
        tmp = __s("HTTP_%s", it->key);
        char *s = tmp;
        while (*s)
        {
            if (*s == '-')
                *s = '_';
            else if (*s != '_')
                *s = toupper((char)*s);
            s++;
        }
        add_vars(&env_vars, tmp, (char *)it->value);
        free(tmp);
    }
    tmp = (char *)dvalue(request, "RESOURCE_PATH");
    if (tmp)
    {
        add_vars(&env_vars, "SCRIPT_NAME", tmp);
        tmp = __s("%s/%s", __plugin__->htdocs, tmp);
        add_vars(&env_vars, "SCRIPT_FILENAME", tmp);
        add_vars(&env_vars, "PATH_TRANSLATED", tmp);
        free(tmp);
    }
    else
    {
        add_vars(&env_vars, "SCRIPT_FILENAME", "");
        add_vars(&env_vars, "PATH_TRANSLATED", "");
        add_vars(&env_vars, "SCRIPT_NAME", "");
    }
    // redirect status for php
    add_vars(&env_vars, "REDIRECT_STATUS", "200");
    return env_vars;
}

void *handle(void *data)
{
    antd_request_t *rq = (antd_request_t *)data;
    void *cl = (void *)rq->client;
    pid_t pid = 0;
    int inpipefd[2];
    int outpipefd[2];
    char buf[BUFFLEN];
    int status;
    antd_task_t *task = NULL;
    list env_vars = NULL;
    char *bin = get_cgi_bin(rq);
    if (!bin)
    {
        LOG("No cgi bin found\n");
        unknow(cl);
        task = antd_create_task(NULL, data, NULL,rq->client->last_io);
        task->priority++;
        return task;
    }
    env_vars = get_env_vars(rq);
    // now exec the cgi bin
    LOG("Execute the cgi bin\n");
    item np = env_vars;
    int size = list_size(env_vars);
    char **envs = (char **)malloc((size + 1) * sizeof(*envs));
    envs[size] = NULL;
    int i = 0;
    while (np)
    {
        envs[i] = np->value.s;
        np = np->next;
        i++;
    }
    // PIPE
    pipe(inpipefd);
    pipe(outpipefd);
    pid = fork();
    if (pid == 0)
    {
        // Child
        dup2(outpipefd[0], STDIN_FILENO);
        dup2(inpipefd[1], STDOUT_FILENO);
        dup2(inpipefd[1], STDERR_FILENO);

        //ask kernel to deliver SIGTERM in case the parent dies
        //prctl(PR_SET_PDEATHSIG, SIGTERM);
        char *argv[] = {bin, 0};
        execve(argv[0], &argv[0], envs);
        // Nothing below this line should be executed by child process. If so,
        // it means that the execl function wasn't successfull, so lets exit:
        _exit(1);
    }
    // The code below will be executed only by parent.

    //close unused pipe ends
    close(outpipefd[0]);
    close(inpipefd[1]);

    // Now, we can write to outpipefd[1] and read from inpipefd[0] :
    write_request_body(rq, outpipefd[1]);

    set_status(cl, 200, "OK");
    //wpid = 0;
    //waitpid(pid, &status, 0); // wait for the child finish
    // WNOHANG
    while (1)
    {
        memset(buf, 0, sizeof(buf));
        ssize_t count = read(inpipefd[0], buf, BUFFLEN);
        if (count == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                break;
            }
        }
        else if (count == 0)
        {
            break;
        }
        else
        {
            antd_send(cl, buf, count);
        }
    }
    /*
    do {
        memset(buf, 0, sizeof(buf));
        int r = read(inpipefd[0], buf, BUFFLEN-1);
        if(r > 0)
        {
            __t(cl, buf);
        }
    } while(wpid == 0);
    */
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    free(envs);
    list_free(&env_vars);
    task = antd_create_task(NULL, data, NULL,rq->client->last_io);
    task->priority++;
    return task;
}
