#define PLUGIN_IMPLEMENT 1
#include <sys/wait.h>
#include <antd/plugin.h>
#include "antd/ini.h"

#define MAX_ENV_SIZE 512

dictionary_t cgi_bin = NULL;

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

static void add_vars(list_t *l, char *k, char *v)
{
    if (!v || !l || !k)
        return;
    char *data = __s("%s=%s", k, v);
    list_put_ptr(l, data);
}

static void write_request_body(antd_request_t *rq, int fd)
{
    char *tmp = (char *)dvalue(rq->request, "METHOD");
    if (!tmp || EQU(tmp, "GET") || EQU(tmp, "HEAD"))
        return;
    int clen = -1;
    dictionary_t header = (dictionary_t)dvalue(rq->request, "REQUEST_HEADER");
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
            UNUSED(write(fd, buf, stat));
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
static list_t get_env_vars(antd_request_t *rq)
{
    char *tmp = NULL;
    char *sub = NULL;
    dictionary_t request = (dictionary_t)rq->request;
    dictionary_t header = (dictionary_t)dvalue(rq->request, "REQUEST_HEADER");
    list_t env_vars = list_init();
    add_vars(&env_vars, "GATEWAY_INTERFACE", "CGI/1.1");
    add_vars(&env_vars, "SERVER_SOFTWARE", SERVER_NAME);
    tmp = (char *)dvalue(request, "REQUEST_QUERY");
    if (!tmp)
        add_vars(&env_vars, "QUERY_STRING", "");
    else
    {
        add_vars(&env_vars, "REQUEST_URI", tmp);
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
    add_vars(&env_vars, "DOCUMENT_ROOT", rq->client->port_config->htdocs);
    tmp = (char *)dvalue(request, "REQUEST_PATH");
    if (tmp)
    {
        sub = tmp;
        while(*sub == '/') sub++;
        if(sub)
        {
            add_vars(&env_vars, "PATH_INFO", sub);
        }
        else
        {
            add_vars(&env_vars, "PATH_INFO", "");
        }
    }
    else
        add_vars(&env_vars, "PATH_INFO", "");
    tmp = (char *)dvalue(header, "REMOTE_ADDR");
    add_vars(&env_vars, "REMOTE_ADDR", tmp);
    add_vars(&env_vars, "REMOTE_HOST", tmp);
    add_vars(&env_vars, "SERVER_NAME", SERVER_NAME);
    add_vars(&env_vars, "SERVER_PORT", (char *)dvalue(header, "SERVER_PORT"));
    add_vars(&env_vars, "SERVER_PROTOCOL", "HTTP/1.1");
    // add remaining header to the vars
    chain_t it;
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
        tmp = __s("%s/%s", rq->client->port_config->htdocs, tmp);
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


int read_line(int fn, char*buf,int size)
{
	int i = 0;
	char c = '\0';
	int n;
	while ((i < size - 1) && (c != '\n'))
	{
		n = read(fn, &c,1);
		if (n > 0)
		{
			//LOG("Data : %c\n", c);
			buf[i] = c;
			i++;
		}
		else
			c = '\n';
	}
	buf[i] = '\0';
	return i;
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
    list_t env_vars = NULL;
    char *bin = get_cgi_bin(rq);
    if (!bin)
    {
        LOG("No cgi bin found\n");
        antd_error(cl,503, "Service unavailable");
        task = antd_create_task(NULL, data, NULL,rq->client->last_io);
        task->priority++;
        return task;
    }
    env_vars = get_env_vars(rq);
    // now exec the cgi bin
    LOG("Execute the cgi bin\n");
    item_t np = env_vars;
    char* envs[MAX_ENV_SIZE];
    int i = 0;
    while (np)
    {
        envs[i] = (char*)np->value.ptr;
        np = np->next;
        i++;
        if(i == MAX_ENV_SIZE - 1)
            break;
    }
    envs[i] = NULL;
    // PIPE
    UNUSED(pipe(inpipefd));
    UNUSED(pipe(outpipefd));
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

    const char* stat_str = get_status_str(200);
    //set_status(cl, 200, "OK");
    //wpid = 0;
    //waitpid(pid, &status, 0); // wait for the child finish
    // WNOHANG
    int beg = 1;
    regmatch_t matches[2];
    char statusbuf[100];
    char* sub = NULL;
	memset(statusbuf, '\0', sizeof(statusbuf));
    while ( waitpid(pid, &status, WNOHANG) == 0)
    {
        memset(buf, 0, sizeof(buf));
        ssize_t count = read(inpipefd[0], buf, BUFFLEN - 1);
        if (count == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                //perror("read");
                break;
            }
        }
        else if (count == 0)
        {
           continue;
        }
        else
        {
            sub = buf;
            if(beg)
            {
                if(regex_match("\\s*Status\\s*:\\s+([0-9]{3}\\s+[a-zA-Z0-9 ]*)",buf,2,matches))
                {
                    memcpy(statusbuf, buf + matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);
                    sub = buf + matches[1].rm_eo + 2;
                    count -= matches[1].rm_eo + 2;
                    __t(cl, "HTTP/1.1 %s", statusbuf);
                }
                else
                {
                    __t(cl, "HTTP/1.1 %d %s", 200, stat_str);
                }
                beg = 0;
            }
            antd_send(cl, sub, count);
            //printf("sent: %d with count: %d\n", sent, count);
        }
    }
    //kill(pid, SIGKILL);
    //waitpid(pid, &status, 0);
    //printf("End cgi\n");
    free(envs);
    list_free(&env_vars);
    task = antd_create_task(NULL, data, NULL,rq->client->last_io);
    task->priority++;
    return task;
}
