#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>  
#include <sys/stat.h>
//-Wall -Werror -Wextra -pedantic -Wno-pointer-sign 
/**
 * DEFINE OTHER MACROS
 **/

#define MAXFILELEN 255

/**
 * DEFINE OTHER MACROS END
 **/


/**
 * DEFINE PARAMETER MACROS BEGINNING
**/
#define NUMBEROFNURSES 'n'
#define NUMBEROFVACCINATORS 'v'
#define NUMBEROFCITIZENS 'c'
#define SIZEOFTHEBUFFER 'b'
#define HOWMANYTIMESEACHCITIZENMUSTRECEIVETHETWOSHOTS 't'
#define PATHNAME 'i'
/**
 * DEFINE PARAMETER MACROS END
**/

/**SHARED MEMORY CONTENTS BEGINNING
 * 
 */
struct 
shared_area 
{
    int vaccine_1;
    int vaccine_2;
    int counter;
    int finished_nurse_count;
    int total_vaccine;
    int read;
    int last_vaccinator_pid;
    int last_vaccinator_num;
    int curr_citizen_count;
}shared_area;
/**SHARED MEMORY CONTENTS END

 * FUNCTION THAT PARSES/PRINTS COMMAND-LINE ARGUMENTS BEGINNING
 */
void 
parse_args(int argc, char**argv, int *n, int *v, int *c, int *b, int *t, char *input_file_path);

void 
show_args(int n, int v, int c, int b, int t, char *input_file_path);


/**
 * FUNCTION THAT PARSES/PRINTS COMMAND-LINE ARGUMENTS END
 */

/**
 * MEM ALLOC FUNCTIONS BEGINNING
 * */
void*
robust_calloc(size_t count, size_t size);
/**
 * MEM ALLOC FUNCTIONS END
 * */
/**
 * FILE I/O FUNCTIONS BEGINNING
 */
int
robust_open(const char* file, int flags);
ssize_t
robust_read (int fd, void* buf, size_t size);

ssize_t
robust_write (int fd, const void* buf, size_t size);

void
robust_close(int fd);

void
robust_lock(int fd);
void
robust_unlock(int fd);

ssize_t
robust_pread (int fd, void* buf, size_t size, off_t offset);

/**
 * FILE I/O FUNCTIONS END
 */

/**
 * SHARED MEMORY FUNCTIONS BEGINNING
 * /
 */
void *
robust_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

int
robust_shm_open(const char* file, int flags);

void 
robust_ftruncate(int fd, off_t length);

void
robust_shm_unlink(const char* name);

void print_shared_mem(struct shared_area *s);

/**
 * SHARED MEMORY FUNCTIONS END
 * /
 */



/**
 * SEMAPHORE FUNCTIONS BEGINNING
 * /
 */

void 
robust_sem_getvalue(sem_t *sem, int sval);
void
robust_sem_wait(sem_t *sem);
void 
robust_sem_post(sem_t *sem);
void
robust_semunlink(char *cname);
void
robust_semclose(sem_t *sem);


/**
 * SEMAPHORE FUNCTIONS END
 * /
 */
/**
 * HELPER FUNCTIONS*/
void file_check(char *file_name);


/**
 * 
 *ACTORS
 */


void nurse(int fd, int n, int t, int c, int i);
int vaccinator(int i);
void citizen( int n, int t, int v , int process_no);

int total_child = -1;
pid_t *cur_pid = NULL;
struct shared_area *ptr;
sem_t *mutex;
sem_t *items_1;
sem_t *items_2;
sem_t *spaces;
sem_t *bring_citizen;
sem_t *mutex_citizen;
sem_t *vaccinate;
char child_message[150];

char shared_mem_name[] = "/sharedmem";
char _mutex[] = "/semaphoremutex";
char _items_1[] = "semaphoreitems1";
char _items_2[] = "semaphoreitems2";
char _spaces[] = "/semaphorespaces";
char _bring_citizen[] = "/bringcitizen";
char _mutex_citizen[] = "/mutexcitizen";
char _vaccinate[] = "/vaccinate";
int fd, s_fd; //file descriptor.
int filedes[2];

void clean_explicitly();
int main(int argc, char *argv[])
{
    signal(SIGINT, clean_explicitly);
    int i; //counter.
    int n, v, c, b, t; //command line parameters.
    char file[MAXFILELEN]; //filename.
    
    setbuf(stdout, NULL);

    if (pipe(filedes) == -1)
        perror("pipe");

    /**
     * Parse args
     */
    parse_args(argc, argv, &n, &v, &c, &b, &t, file);

    /**
     * Show args
     */
    //show_args(n, v, c, b, t, file);
    printf("Welcome to the GTU344 clinic. Number of citizen to vaccinate c=%d with t=%d doses.\n", c, t);
    /**
     * Create pids for all children
     */
    //pid_t cur_pid[n + v + c];
    total_child = n + v + c;
    cur_pid = robust_calloc(n + v + c, sizeof(pid_t));

    /**
     * Open the vaccine storage/file.
     */
    fd = robust_open(file, O_RDONLY);

    /**
     * Open shared memory.
     */
    s_fd = robust_shm_open(shared_mem_name, O_RDWR | O_CREAT); 

    /**
     * Allocate space for shared memory.
     **/
    robust_ftruncate(s_fd, sizeof(struct shared_area));

    /**
     * Map the shared memory into a local pointer.
    **/
    ptr = robust_mmap(NULL, sizeof(struct shared_area), PROT_READ | PROT_WRITE, MAP_SHARED, s_fd, 0);

    ptr->vaccine_1 = 0;
    ptr->vaccine_2 = 0;
    ptr->counter = 0;
    ptr->finished_nurse_count = 0;
    ptr->total_vaccine = 2 * t * c;
    ptr->read = 0;
    ptr->curr_citizen_count = c;
    /**
     * OPEN MUTEX SEMAPHORE BEGINNING
     */
    mutex = sem_open(_mutex, O_CREAT | O_EXCL,  0666, 1);
    if(mutex == SEM_FAILED) //The process is either failed or it tries to open second time.
    {   
        perror("sem_open");
        exit(EXIT_FAILURE);
    }
    mutex_citizen = sem_open(_mutex_citizen, O_CREAT | O_EXCL,  0666, 1);
    if(mutex_citizen == SEM_FAILED) //The process is either failed or it tries to open second time.
    {   
        perror("sem_open");
        exit(EXIT_FAILURE);
    }
    /**
     * OPEN MUTEX SEMAPHORE END
     */

     /**
     * OPEN ITEMS SEMAPHORE BEGINNING
     */
    items_1 = sem_open(_items_1, O_CREAT | O_EXCL,  0666, 0);
    if(items_1 == SEM_FAILED) //The process is either failed or it tries to open second time.
    {   
        perror("sem_open");
        exit(EXIT_FAILURE);
    }
    items_2 = sem_open(_items_2, O_CREAT | O_EXCL,  0666, 0);
    if(items_2 == SEM_FAILED) //The process is either failed or it tries to open second time.
    {   
        perror("sem_open");
        exit(EXIT_FAILURE);
    }
    /**
     * OPEN ITEMS SEMAPHORE END
     */

    /**
     * OPEN ITEMS SEMAPHORE BEGINNING
     */
    spaces = sem_open(_spaces, O_CREAT | O_EXCL,  0666, b);
    if(spaces == SEM_FAILED) //The process is either failed or it tries to open second time.
    {   
        perror("sem_open");
        exit(EXIT_FAILURE);
    }

    vaccinate = sem_open(_vaccinate, O_CREAT | O_EXCL,  0666, 1);
    if(vaccinate == SEM_FAILED) //The process is either failed or it tries to open second time.
    {   
        perror("sem_open");
        exit(EXIT_FAILURE);
    }
    /**
     * OPEN ITEMS SEMAPHORE END
     */

    /**
    * OPEN CITIZEN SEMAPHORE BEGINNING
    */
 
    bring_citizen = sem_open(_bring_citizen, O_CREAT | O_EXCL,  0666, 0);
    if(bring_citizen == SEM_FAILED) //The process is either failed or it tries to open second time.
    {   
        perror("sem_open");
        exit(EXIT_FAILURE);
    }
    /**
     * OPEN CITIZEN SEMAPHORE END
     */
        

    /**
     * Create n + v + c processes.
     * */
    for(i = 0; i < n + v + c; i++)
    {
        cur_pid[i]= fork();
        if(cur_pid[i] == 0)
        {
            robust_close(filedes[0]);
            //Nurse Section.
            if(i < n)
            {
                 /* Child - report ID */
                //printf("Nurses, ppid = %d, pid = %d, i = %d\n", getppid(), getpid(), i);
                nurse(fd,n, t, c, i);
                fflush(stdout);
                robust_semclose(mutex);
                robust_semclose(mutex_citizen);
                robust_semclose(items_1);
                robust_semclose(items_2);
                robust_semclose(spaces);
                robust_semclose(bring_citizen);
                robust_semclose(vaccinate);
                free(cur_pid);
                _exit(EXIT_SUCCESS);
            }
            //Vaccinator section.
            else if((i >= n) && (i < n + v))
            {
                 /* Child - report ID */
                //printf("Vaccinators, ppid = %d, pid = %d, i = %d\n", getppid(), getpid(), i);
                int vaccinated_count = vaccinator(i);
                
                snprintf(child_message,150, "Vaccinator %d (pid=%d) vaccinated %d doses.\n", i - n + 1, getpid() ,vaccinated_count);

                robust_write(filedes[1], child_message, sizeof(child_message));
                fflush(stdout);
                robust_semclose(mutex);
                robust_semclose(mutex_citizen);
                robust_semclose(items_1);
                robust_semclose(items_2);
                robust_semclose(spaces);
                robust_semclose(bring_citizen);
                robust_semclose(vaccinate);
                free(cur_pid);
                //robust_close(filedes[1]);
                //printf("Vaccinated count is %d for %d\n",vaccinated_count, getpid());
                _exit(EXIT_SUCCESS);
            }
            //Citizen section.
            else if(i >= n + v)
            {
                 /* Child - report ID */
                //printf("Citizens, ppid = %d, pid = %d, i = %d\n", getppid(), getpid(), i);
                citizen(n, t, v, i);
                fflush(stdout);
                robust_semclose(mutex);
                robust_semclose(mutex_citizen);
                robust_semclose(items_1);
                robust_semclose(items_2);
                robust_semclose(spaces);
                robust_semclose(bring_citizen);
                robust_semclose(vaccinate);
                free(cur_pid);
                _exit(EXIT_SUCCESS);
            }
        }
        else if(cur_pid[i] == -1)
        {
            perror("Fork:");
            fprintf(stderr, "FORK FAILURE. EXITING.\n");
            robust_close(s_fd);
            robust_close(fd);
            robust_shm_unlink(shared_mem_name);
            robust_semclose(bring_citizen);
            robust_semclose(mutex_citizen);
            robust_semclose(mutex);
            robust_semclose(items_1);
            robust_semclose(items_2);
            robust_semclose(spaces);
            robust_semclose(vaccinate);
            robust_semunlink(_mutex);
            robust_semunlink(_items_1);
            robust_semunlink(_items_2);
            robust_semunlink(_spaces);
            robust_semunlink(_bring_citizen);
            robust_semunlink(_mutex_citizen);
            free(cur_pid);
            exit(EXIT_FAILURE);
        }
    }

    
   
    robust_close(filedes[1]);
    //Wait for all children
    for(i = 0; i < n + v + c; i++) {
        int status = 0;
        wait(&status);
        //printf("Parent knows child %d is finished. \n", (int)childpid); 
    }
    while(robust_read(filedes[0], child_message, sizeof(child_message)))
    {
        printf("%s\n", child_message);
    }    
    
    robust_close(filedes[0]);
    printf("The clinic is now closed. Stay healthy\n");
    //print_shared_mem(ptr);
    
    //Close and unlink
    robust_close(s_fd);
    
    robust_close(fd);
    
    
    robust_shm_unlink(shared_mem_name);
    
    
    robust_semclose(bring_citizen);
    robust_semclose(mutex_citizen);
    robust_semclose(mutex);
    robust_semclose(items_1);
    robust_semclose(items_2);
    robust_semclose(spaces);
    robust_semclose(vaccinate);
   
    robust_semunlink(_vaccinate);
    robust_semunlink(_mutex);
    robust_semunlink(_items_1);
    robust_semunlink(_items_2);
    robust_semunlink(_spaces);
    robust_semunlink(_bring_citizen);
    robust_semunlink(_mutex_citizen);
    free(cur_pid);
    
   
    return 0;
}



///program –n 3 –v 2 –c 3 –b 11 –t 3 –i inputfilepath


void 
parse_args(int argc, char**argv, int *n, int *v, int *c, int *b, int *t, char *input_file_path)
{   
    if(argc != 13)
    {
        fprintf(stderr, "Usage: ./program –n 3 –v 2 –c 3 –b 11 –t 3 –i inputfilepath\n");
        exit(EXIT_FAILURE);
    }
    char character;
    while ((character = getopt (argc, argv, "n:v:c:b:t:i:")) != -1)
    {
        switch (character)
        {
            case NUMBEROFNURSES:
                *n = atoi(optarg);
                if(*n < 2)
                {
                    fprintf(stderr, "The n must be >=2\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case NUMBEROFVACCINATORS:
                *v = atoi(optarg);
                if(*v < 2)
                {
                    fprintf(stderr, "The v must be >=2\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case NUMBEROFCITIZENS:
                *c = atoi(optarg);
                if(*c < 3)
                {
                    fprintf(stderr, "The c must be >=3\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case SIZEOFTHEBUFFER:
                *b = atoi(optarg);
                break;
            case HOWMANYTIMESEACHCITIZENMUSTRECEIVETHETWOSHOTS: //weird macro
                *t = atoi(optarg);
                if(*t < 1)
                {
                    fprintf(stderr, "The t must be >=1\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case PATHNAME:
                if(strlen(optarg) > MAXFILELEN)
                {
                    fprintf(stderr, "Linux file length can't be bigger than 256, exiting the program.\n");   
                    exit(EXIT_FAILURE);         
                }
                else
                {
                  strcpy(input_file_path, optarg);
                }
                break;
            default:
                fprintf(stderr,"Invalid operation. Exiting\n.");
                exit(EXIT_FAILURE);
        }
    }
    if((*b) < (*t) * (*c) + 1)
    {
        fprintf(stderr, "The b must be  >= tc+1\n");   
        exit(EXIT_FAILURE);   
    }
}


void print_shared_mem(struct shared_area *s)
{
    printf("===============================================================\n");
    printf("Process %d reporting:\n", getpid());

    printf("\nVaccine_1 Count: %d\n\nVaccine_2 Count: %d\n ", s->vaccine_1, s->vaccine_2);
    printf("\nFinished Nurse Count : %d\n", s->finished_nurse_count);
    printf("\nCounter: %d\n", s->counter);
    printf("\nTotal Vaccines %d\n", s->total_vaccine);
    
    printf("===============================================================\n");
}

void 
show_args(int n, int v, int c, int b, int t, char *input_file_path)
{
    printf("Number of nurses: %d\nNumber of vaccinators: %d\nNumber of citizens: %d\nSize of the buffer: %d\nEach citizen will receive 2 shots :%d\n",n,v,c,b,t);
    printf("Input file path: %s\n", input_file_path);
}

int
robust_open(const char* file, int flags){
    int fd;
    if ((fd = open(file, flags, 0666)) < 0)
    {
        perror("open");
        exit(EXIT_FAILURE);
    }
    return fd;
}

void
robust_close(int fd)
{
    if(close(fd) == -1)
    {
        perror("close");
        exit(EXIT_FAILURE);
    }
}
void* 
robust_calloc(size_t count, size_t size)
{
    void* p;
    if ((p = calloc(count, size)) == NULL)
    {
        fprintf(stderr, "Calloc encountered an error. Exiting the program.\n");
        exit(EXIT_FAILURE);
    }
    return p;
}

ssize_t
robust_read (int fd, void* buf, size_t size)
{
    ssize_t ret;
    
    do
    {
        ret = read(fd, buf, size);
    } while ((ret < 0) && (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN));
    if (ret < 0)
    {
        perror("read");
        exit(EXIT_FAILURE);
    }
    return ret;
}

void clean_explicitly()
{
    /*It's fine to use write system call inside a signal handler because it's Reentrant*/ 
    robust_write(STDOUT_FILENO, "CTRL-C CATCHED. TERMINATING GRACEFULLY.\n", sizeof("CTRL-C CATCHED. TERMINATING GRACEFULLY.\n"));
    int i;
    int child_status;
    /**
     * FREE RESOURCES FOR PARENT BEGINNING
     * */
    robust_close(s_fd);
    robust_close(fd);
    robust_shm_unlink(shared_mem_name);
    robust_semclose(bring_citizen);
    robust_semclose(mutex_citizen);
    robust_semclose(mutex);
    robust_semclose(items_1);
    robust_semclose(items_2);
    robust_semclose(spaces);
    robust_semclose(vaccinate);
    robust_semunlink(_vaccinate);
    robust_semunlink(_mutex);
    robust_semunlink(_items_1);
    robust_semunlink(_items_2);
    robust_semunlink(_spaces);
    robust_semunlink(_bring_citizen);
    robust_semunlink(_mutex_citizen);
    free(cur_pid);
    /**
     * FREE RESOURCES FOR PARENT END
     * */
    /**
     * TERMINATE THE CHILD PROCESSES.*/
    for(i = 0 ; i < total_child ; ++i)
    {
        kill(cur_pid[i], SIGTERM);
    }
    /**
     * REAP TERMINATED CHILDREN IN CASE OF ANY ZOMBIES*/
    for (i = 0; i < total_child; i++) 
    {
        wait(&child_status);
    }
    exit(EXIT_FAILURE);
}
ssize_t
robust_write (int fd, const void* buf, size_t size)
{
    ssize_t ret;
    
    do
    {
        ret = write(fd, buf, size);
    } while ((ret < 0) && (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN));
    if (ret < 0)
    {
        perror("write");
        exit(EXIT_FAILURE);
    }
    return ret;
}
ssize_t
robust_pread (int fd, void* buf, size_t size, off_t offset)
{
    ssize_t ret;
    
    do
    {   
        ret = pread(fd, buf, size, offset);
    } while ((ret < 0) && (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN));
    if (ret < 0)
    {
        perror("read");
        exit(EXIT_FAILURE);
    }
    return ret;
}

void file_check(char *file_name)
{
    FILE *filePointer;
    char ch;
    int one_counter = 0;
    int two_counter = 0;
    filePointer = fopen(file_name, "r");

   
    if (filePointer == NULL)
    {
        printf("File is not available \n");
    }
    else
    {
    
        while ((ch = fgetc(filePointer)) != EOF)
        {
            if(ch == '1')
            {
                one_counter++;
            }
            else if(ch == '2')
            {
                two_counter++;
            }
        }
    }
    printf("The file has %d 1's and %d 2's.\n", one_counter, two_counter);
    fclose(filePointer);
}

void
robust_lock(int fd){
    struct flock fl = { F_WRLCK, SEEK_SET, 0,       0,     0 };
    fl.l_type = F_WRLCK;
    if (fcntl (fd, F_SETLKW, &fl) == -1)
        perror("fcntl");
}
void
robust_unlock(int fd){
    struct flock fl = { F_WRLCK, SEEK_SET, 0,       0,     0 };
    fl.l_type = F_UNLCK;
    if (fcntl (fd, F_SETLK, &fl ) == -1)
        perror("fcntl");
}
void *
robust_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    addr = mmap(NULL, length, prot, flags,fd, offset);
    if (addr == MAP_FAILED)
    {
        fprintf(stderr,"mmap fails.\n");
        exit(EXIT_FAILURE);
    }
    return addr;
}
int
robust_shm_open(const char* file, int flags)
{
    int fd;
    if ((fd = shm_open(file, flags, 0666)) < 0)
    {
        if(fd == O_EXCL)
        {
            fprintf(stdout, "Tried to open a shared mem again.\n");
        }
        else
        {
            perror("shm_open");
            exit(EXIT_FAILURE);
        }
        
    }
    return fd;
}

 void 
 robust_ftruncate(int fd, off_t length)
 {
     if(ftruncate(fd, length) == -1)
     {
         perror("ftruncate fails: ");
         exit(EXIT_FAILURE);
     }
 }
void
robust_shm_unlink(const char* name)
{
    if (shm_unlink(name) == -1)
        fprintf(stderr,"sem_unlink fails.");
}

void 
robust_sem_getvalue(sem_t *sem, int sval)
{
    if (sem_getvalue(sem, &sval) == -1) 
    {
        fprintf(stderr, "Semgetvalue returned error.\n");
        exit(EXIT_FAILURE);
    }
}
//https://stackoverflow.com/questions/63168815/producer-consumer-task-problem-with-correct-writing-to-shared-buffer
void
robust_sem_wait(sem_t *s)
{
    int  result;
    do {
        result = sem_wait(s);
    } while (result == -1 && errno == EINTR);
    if (result < 0)
    {
        perror("semwait");
        exit(EXIT_FAILURE);
    }
}
void 
robust_sem_post(sem_t *sem)
{
    if (sem_post(sem) == -1)
    {
        fprintf(stderr, "Semwait returned error.\n");
        exit(EXIT_FAILURE);
    }   
}

void
robust_semunlink(char *cname)
{
    if(sem_unlink(cname) == -1)
    {
        fprintf(stderr, "SemUnlink fails.\n");
        exit(EXIT_FAILURE);
    }
        
}
void
robust_semclose(sem_t *sem)
{
    if(sem_close(sem) == -1)
    {
        fprintf(stderr, "SemClose fails.\n");
        exit(EXIT_FAILURE);
    }
        
}


void nurse(int fd, int n, int t, int c, int i)
{
    int read_count;
    char buf[1 + 1];
    int vaccine_type;
    do
    {
        /**
         * We will write one byte so space--;
         * */
        robust_sem_wait(spaces); 
        /**
         * Lock
         */
        robust_sem_wait(mutex); 
        /**
         * If read byte count is equals to buffer size terminate one of the nurses
         */
        if(ptr->counter >= 2 * t * c)
        {
            ptr->finished_nurse_count++;
            /*If all nurses have terminated, notify.*/
            if(ptr->finished_nurse_count == n)
            {
                printf("Nurses have carried all vaccines to the buffer, terminating.\n");
            }
            /*Let consumers terminate.*/
            robust_sem_post(items_1);
            robust_sem_post(items_2);
            /*We didn't add anything to buffer, increment the spaces back.*/
            robust_sem_post(spaces);
            /*Unlock and exit. Two statements are not atomic together but no problem with that.*/
            robust_sem_post(mutex);
            //exit(EXIT_SUCCESS);
            return;
        }
        /*Read single byte from file with the help of ptr->counter offset..*/
        read_count = robust_pread(fd, buf, 1, ptr->counter);
        /*Increment the offset*/
        ptr->counter++;
        /*Don't forget to place null character*/
        buf[read_count] = '\0';
        /*Convert str to int*/
        vaccine_type = atoi(buf);
        /*If the vaccine type is '1', increment ptr->vaccine_1 and report.*/
        if(vaccine_type == 1)
        {
            ptr->vaccine_1++;
            printf("Nurse %d (pid = %d) has brought vaccine 1: the clinic has %d vaccine1 and %d vaccine2.\n",
            i+1,getpid(), ptr->vaccine_1, ptr->vaccine_2);
        }
        /*If the vaccine type is '2', increment ptr->vaccine_1 and report.*/
        else if(vaccine_type == 2)
        {
            ptr->vaccine_2++;
            printf("Nurse %d (pid = %d) has brought vaccine 2: the clinic has %d vaccine1 and %d vaccine2.\n",
            i+1,getpid(), ptr->vaccine_1, ptr->vaccine_2);
        } 
        /*Release the lock*/
        robust_sem_post(mutex);
        /*Increment the item count*/
        if(vaccine_type == 1)
        {
            robust_sem_post(items_1);
        }
        else
        {
            robust_sem_post(items_2);
        }
        
        if(read_count == 0)
        {
            printf("EOF ENCOUNTERED\n");
        }
    } while (read_count > 0);
}

int vaccinator(int i)
{
    int vaccinated_count = 0;
    while(1)
    {
        /*We'll be popping 2 elements so call items twice.*/
        robust_sem_wait(items_1);
        robust_sem_wait(items_2);
        /*Lock*/
        robust_sem_wait(mutex);
        
        /*If buffer's size is an odd number then the remaning vaccine will be 1. If it's even then it will be 0.*/
        /*Actually it's specified that the buffer says will always be an even number. I could do it as == 0*/
        if(ptr->total_vaccine <= 1)//Buffersize control
        {
            /*We didn't consume 2 items, give them back*/
            robust_sem_post(items_1);
            robust_sem_post(items_2);
            /*Unlock and break*/
            robust_sem_post(mutex);
            //printf("Vaccinator %d finished it's job.\n", getpid());
            break;
        }      
        /*If we have both type of vaccines then we should decrement the vaccines and apply vaccines to citizens.*/
        else
        {
            /*Increment*/
            //print_shared_mem(ptr);
            ptr->total_vaccine-=2;
            vaccinated_count+=2;
            ptr->read+=2;
           
            ptr->last_vaccinator_pid = getpid();
            ptr->last_vaccinator_num = i;
            robust_sem_post(bring_citizen);

            //robust_sem_wait(vaccinate);//suspicious
            //robust_sem_post(spaces);
            //robust_sem_post(spaces);
        }
        robust_sem_post(mutex);
    }
    return vaccinated_count;
}


void citizen( int n, int t, int v, int process_no)
{
    int i = 1;
    while(i <= t)
    {
        robust_sem_wait(bring_citizen);
        robust_sem_wait(mutex_citizen);
        ptr->vaccine_1--;
        ptr->vaccine_2--;
        robust_sem_post(spaces);
        robust_sem_post(spaces);
        robust_sem_post(mutex_citizen);
        //printf("Citizen %d gets vaccinated %d. time\n", getpid(),i++);
        printf("Vaccinator %d (pid=%d) is inviting citizen pid=%d to the clinic.\n",
        ptr->last_vaccinator_num, ptr->last_vaccinator_pid, getpid());
        printf("Citizen %d (pid=%d) is vaccinated for the %dth time: the clinic has %d vaccine1 and %d vaccine2.\n",
        process_no - n - v + 1, getpid(),i, ptr->vaccine_1, ptr->vaccine_2 );
        if(t == i)
        {
            //robust_sem_wait(mutex_citizen);
            robust_sem_wait(vaccinate);
            ptr->curr_citizen_count--;
            robust_sem_post(vaccinate);
            printf("The citizen is leaving. Remaining citizens to vaccinate: %d.\n", ptr->curr_citizen_count);
            if(ptr->curr_citizen_count == 0)
            {
                printf("All citizens have been vaccinated.\n");
            }
            //robust_sem_post(mutex_citizen);
            
        }
        
        i++;
    } 
    //printf("Citizen[%d] quits.\n", getpid());   
}
