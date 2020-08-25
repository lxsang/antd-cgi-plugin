#define PLUGIN_IMPLEMENT 1
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <antd/plugin.h>
#include <antd/scheduler.h>
#include <antd/ini.h>
#include <ctype.h>

#define MAX_ENV_SIZE 100

dictionary_t cgi_bin = NULL;


typedef struct {
    int size;
    char* env[MAX_ENV_SIZE];
} envar_arr_t;

static int ini_handle(void *user_data, const char *section, const char *name,
                      const char *value)
{
    UNUSED(user_data);
    if (EQU(section, "CGI"))
    {
        dput(cgi_bin, name, strdup(value));
        LOG("put %s for %s", value, name);
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
        ERROR("Can't load '%s'", file);
    }
    else
    {
        LOG("CGI config loaded");
    }
    free(cnf);
    free(file);
}
void destroy()
{
    if (cgi_bin)
        freedict(cgi_bin);
}

static void add_vars(envar_arr_t *l, char *k, char *v)
{
    if (!v || !l || !k)
        return;
    if(l->size >= MAX_ENV_SIZE-1)
        return;
    char *data = __s("%s=%s", k, v);
    l->env[l->size] = data;
    l->size++;
    //list_put_ptr(l, data);
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
    LOG("CGI  CMD: %s", bin);
    free(tmp);
    return bin;
}
static void get_env_vars(antd_request_t *rq, envar_arr_t* env_vars)
{
    char *tmp = NULL;
    char *sub = NULL;
    char* root;
    dictionary_t request = (dictionary_t)rq->request;
    dictionary_t header = (dictionary_t)dvalue(rq->request, "REQUEST_HEADER");
    add_vars(env_vars, "GATEWAY_INTERFACE", "CGI/1.1");
    add_vars(env_vars, "SERVER_SOFTWARE", SERVER_NAME);
    root = (char*)dvalue(header, "SERVER_WWW_ROOT");
    tmp = (char *)dvalue(request, "REQUEST_QUERY");
    if (!tmp)
        add_vars(env_vars, "QUERY_STRING", "");
    else
    {
        add_vars(env_vars, "REQUEST_URI", tmp);
        sub = strchr(tmp, '?');
        if (sub)
        {
            sub++;
            add_vars(env_vars, "QUERY_STRING", sub);
        }
        else
            add_vars(env_vars, "QUERY_STRING", "");
    }
    tmp = (char *)dvalue(request, "METHOD");
    if (tmp)
        add_vars(env_vars, "REQUEST_METHOD", tmp);
    tmp = (char *)dvalue(header, "Content-Type");
    if (tmp)
        add_vars(env_vars, "CONTENT_TYPE", tmp);
    else
        add_vars(env_vars, "CONTENT_TYPE", "");
    tmp = (char *)dvalue(header, "Content-Length");
    if (tmp)
        add_vars(env_vars, "CONTENT_LENGTH", tmp);
    else
        add_vars(env_vars, "CONTENT_LENGTH", "");
    add_vars(env_vars, "DOCUMENT_ROOT", root);
    tmp = (char *)dvalue(request, "REQUEST_PATH");
    if (tmp)
    {
        sub = tmp;
        while(*sub == '/') sub++;
        if(sub)
        {
            add_vars(env_vars, "PATH_INFO", sub);
        }
        else
        {
            add_vars(env_vars, "PATH_INFO", "");
        }
    }
    else
        add_vars(env_vars, "PATH_INFO", "");
    tmp = (char *)dvalue(header, "REMOTE_ADDR");
    add_vars(env_vars, "REMOTE_ADDR", tmp);
    add_vars(env_vars, "REMOTE_HOST", tmp);
    add_vars(env_vars, "SERVER_NAME", SERVER_NAME);
    add_vars(env_vars, "SERVER_PORT", (char *)dvalue(header, "SERVER_PORT"));
    add_vars(env_vars, "SERVER_PROTOCOL", "HTTP/1.1");
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
        add_vars(env_vars, tmp, (char *)it->value);
        free(tmp);
    }
    tmp = (char *)dvalue(request, "RESOURCE_PATH");
    if (tmp)
    {
        add_vars(env_vars, "SCRIPT_NAME", tmp);
        tmp = __s("%s/%s", root, tmp);
        add_vars(env_vars, "SCRIPT_FILENAME", tmp);
        add_vars(env_vars, "PATH_TRANSLATED", tmp);
        free(tmp);
    }
    else
    {
        add_vars(env_vars, "SCRIPT_FILENAME", "");
        add_vars(env_vars, "PATH_TRANSLATED", "");
        add_vars(env_vars, "SCRIPT_NAME", "");
    }
    // redirect status for php
    add_vars(env_vars, "REDIRECT_STATUS", "200");
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
        {
            if(i == 0)
                i = n;
            c = '\n';
        }
	}
    if(i >= 0)
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
    char *bin = get_cgi_bin(rq);
    antd_task_t *task = NULL;
    if (!bin || ws_enable(rq->request))
    {
        LOG("No cgi bin found or connection is websocket");
        antd_error(cl,503, "Service unavailable");
        task = antd_create_task(NULL, data, NULL,rq->client->last_io);
        task->priority++;
        return task;
    }
    // PIPE
    UNUSED(pipe(inpipefd));
    UNUSED(pipe(outpipefd));
    pid = fork();
    if (pid == 0)
    {
        // Child
        dup2(outpipefd[0], STDIN_FILENO);
        dup2(inpipefd[1], STDOUT_FILENO);
        // we dont wan't error message on stderr on the returned result
        //dup2(inpipefd[1], STDERR_FILENO);
        // now exec the cgi bin
        LOG("Execute the cgi bin");
        envar_arr_t envs;
        envs.size = 0;
        for(int i = 0; i < MAX_ENV_SIZE; i++)
        {
            envs.env[i] = NULL;
        }
        get_env_vars(rq, &envs);
        //ask kernel to deliver SIGTERM in case the parent dies
        //prctl(PR_SET_PDEATHSIG, SIGTERM);
        char *argv[] = {bin, 0};
        execve(argv[0], &argv[0], envs.env);
        // Nothing below this line should be executed by child process. If so,
        // it means that the execl function wasn't successfull, so lets exit:
        _exit(1);
    }

    // The code below will be executed only by parent.

    char buf[BUFFLEN];
    int status;
    //close unused pipe ends
    close(outpipefd[0]);
    close(inpipefd[1]);

    // Now, we can write to outpipefd[1] and read from inpipefd[0] :
    write_request_body(rq, outpipefd[1]);
    regmatch_t matches[3];
    //fd_set rfd;
    //struct timeval timeout;
	
    memset(buf, 0, sizeof(buf));
    antd_response_header_t rhd;
    rhd.header = dict();
    rhd.cookie = list_init();
    rhd.status = 200;
    char* k;
    char* v;
    int len;
    ssize_t count;
   
    while( read_line(inpipefd[0], buf, BUFFLEN) > 0 && strcmp(buf,"\r\n") != 0)
    {
        trim(buf,'\n');
        trim(buf,'\r');
        if(regex_match("\\s*Status\\s*:\\s+([0-9]{3})\\s+([a-zA-Z0-9 ]*)",buf,3,matches))
        {
            len = matches[1].rm_eo - matches[1].rm_so;
            k = (char*)malloc(len);
            memset(k, 0, len);
            memcpy(k, buf + matches[1].rm_so, len);
            rhd.status = atoi(k);
            free(k);
        }
        else if(regex_match("^([a-zA-Z0-9\\-]+)\\s*:\\s*(.*)$",buf,3,matches))
        {
            len = matches[1].rm_eo - matches[1].rm_so;
            k = (char*)malloc(len+1);
            memcpy(k, buf + matches[1].rm_so, len);
            k[len] = '\0';
            verify_header(k);
            len = matches[2].rm_eo - matches[2].rm_so ;
            v = (char*)malloc(len+1);
            memcpy(v, buf + matches[2].rm_so, len);
            v[len] = '\0';
            if(strcmp(k,"Set-Cookie") == 0)
            {
                list_put_ptr(&rhd.cookie,v);
            }
            else
            {
                dput(rhd.header, k, v);
            }
            free(k);
        }
        else
        {
            LOG("Ignore invalid header: %s", buf);
        }
    }
    antd_send_header(rq->client, &rhd);
    // send out the rest of data
    while (1)
    {
        count = read(inpipefd[0], buf, BUFFLEN);
        
        if (count == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                ERROR("Read: %s", strerror(errno));
                break;
            }
        }

        else if (count == 0)
        {
            if(waitpid(pid, &status, WNOHANG) != 0)
            {
                break;
            }
           continue;
        }
        else
        {
            UNUSED(antd_send(cl, buf, count));
        }
    }

    kill(pid, SIGKILL);
    //waitpid(pid, &status, 0);
    task = antd_create_task(NULL, data, NULL,rq->client->last_io);
    task->priority++;
    return task;
}
