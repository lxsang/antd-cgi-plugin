#include "plugin.h"

void init()
{

}
void destroy()
{

}

static void add_vars(list* l, char* k, char* v)
{
    if(!v || !l || !k) return;
    char* data = __s("%s=%s", k, v);
    list_put_s(l, data);
    free(data);
}

void* handle(void* data)
{
    antd_request_t *rq = (antd_request_t *)data;
    plugin_header_t* __plugin__ = meta();
	void *cl = (void *)rq->client;
    antd_task_t* task = NULL; 
    char* tmp = NULL;
    char* sub = NULL;
    task = antd_create_task(NULL, data, NULL);
    task->priority++;
    dictionary request = (dictionary) rq->request;
    dictionary header = (dictionary) dvalue(rq->request,"REQUEST_HEADER");
    list env_vars = list_init();
    add_vars(&env_vars, "GATEWAY_INTERFACE", "CGI/1.1");
    add_vars(&env_vars, "SERVER_SOFTWARE",SERVER_NAME);
    tmp = (char*)dvalue(request, "REQUEST_QUERY");
    if(!tmp)
        add_vars(&env_vars, "QUERY_STRING", "");
    else
    {
        sub = strchr(tmp,'?');
        if(sub)
        {
            sub++;
            add_vars(&env_vars, "QUERY_STRING", sub);
        }
        else
            add_vars(&env_vars, "QUERY_STRING", "");
    }
    tmp = (char*)dvalue(request, "METHOD");
    if(tmp)
        add_vars(&env_vars, "REQUEST_METHOD", tmp);
    tmp = (char*)dvalue(header, "Content-Type");
    if(tmp)
        add_vars(&env_vars, "CONTENT_TYPE", tmp);
    else
        add_vars(&env_vars, "CONTENT_TYPE", "");
    tmp = (char*)dvalue(header, "Content-Length");
    if(tmp)
        add_vars(&env_vars, "CONTENT_LENGTH", tmp);
    else
        add_vars(&env_vars, "CONTENT_LENGTH", "");
    add_vars(&env_vars, "DOCUMENT_ROOT", __plugin__->htdocs);
    tmp = (char*) dvalue(request, "REQUEST_PATH");
    if(tmp)
        add_vars(&env_vars, "PATH_INFO", tmp);
    else
        add_vars(&env_vars, "PATH_INFO", "");
    tmp = (char*) dvalue(header,"REMOTE_ADDR");
    add_vars(&env_vars, "REMOTE_ADDR", tmp);
    add_vars(&env_vars, "REMOTE_HOST", tmp);
    add_vars(&env_vars, "SERVER_NAME", SERVER_NAME);
    add_vars(&env_vars, "SERVER_PORT", (char*) dvalue(header, "SERVER_PORT"));
    add_vars(&env_vars, "SERVER_PROTOCOL", "HTTP/1.1");
    // add remaining header to the vars
    association it;
    for_each_assoc(it, header)
    {
        tmp = __s("HTTP_%s", it->key);
        char *s = tmp;
        while (*s) {
            if(*s == '-')
                *s = '_';
            else if(*s != '_')
                *s = toupper((char) *s);
            s++;
        }
        add_vars(&env_vars, tmp, (char*)it->value);
        free(tmp);
    }
    tmp = (char*)dvalue(request, "RESOURCE_PATH");
    if(tmp)
    {
        add_vars(&env_vars, "SCRIPT_NAME", tmp);
        tmp = __s("%s/%s",__plugin__->htdocs, tmp);
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
    // now exec the cgi bin
    item np = env_vars;
    int size = list_size(env_vars);
    char** envs = (char**) malloc((size+1)*sizeof(*envs));
    envs[size] = NULL;
    int i = 0;
	while(np)
	{
		envs[i] = np->value.s;
        np = np->next;
        i++;
	}
    /*
    pid_t pid = 0;
    int inpipefd[2];
    int outpipefd[2];
    char buf[256];
    char msg[256];
    int status;

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

        //replace tee with your process
        execve("printenv > env.txt", NULL, envs);
        free(envs);
        list_free(&env_vars);
        // Nothing below this line should be executed by child process. If so, 
        // it means that the execl function wasn't successfull, so lets exit:
        _exit(1);
    }
    // The code below will be executed only by parent. You can write and read
    // from the child using pipefd descriptors, and you can send signals to 
    // the process using its pid by kill() function. If the child process will
    // exit unexpectedly, the parent process will obtain SIGCHLD signal that
    // can be handled (e.g. you can respawn the child process).

    //close unused pipe ends
    close(outpipefd[0]);
    close(inpipefd[1]);

    // Now, you can write to outpipefd[1] and read from inpipefd[0] :  
    while(1)
    {
        printf("Enter message to send\n");
        scanf("%s", msg);
        if(strcmp(msg, "exit") == 0) break;

        write(outpipefd[1], msg, strlen(msg));
        int r = read(inpipefd[0], buf, 256);
        if(r > 0)
        {
            printf("Received answer: %s\n", buf);

        }
    }

    //kill(pid, SIGKILL); //send SIGKILL signal to the child process
    waitpid(pid, &status, 0);*/
    //char *argv[] = { "printenv > /Users/mrsang/Documents/build/www/env.txt", 0 };
    //execve(argv[0],&argv[0], envs);
    char *argv[] = { "/usr/local/bin/php-cgi", 0 };
    execve(argv[0], &argv[0], envs);

    free(envs);
    list_free(&env_vars);
    unimplemented(cl);
    return task;
}