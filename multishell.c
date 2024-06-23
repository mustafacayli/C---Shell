/*
Grup Uyeleri:
Mustafa Çaylı 21120205034
Kamil Şen     21120205045
Talha Karahan 21120205037
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>

#define INBUF_SIZE 256

#define MY_FILE_SIZE 1024
#define MY_SHARED_FILE_NAME "/sharedlogfile"

char *addr = NULL;
int fd = -1;


int initmem()
{   
    shm_unlink(MY_SHARED_FILE_NAME);
    fd = shm_open(MY_SHARED_FILE_NAME,
                  O_CREAT | O_RDWR | O_TRUNC, 0666);
    if (fd < 0){
        perror("multishell.c:open file:");
        exit(1);
    }
    if (ftruncate(fd, MY_FILE_SIZE) == -1){
        perror("ftruncate");
        exit(1);
    }

    addr = mmap(NULL, MY_FILE_SIZE,
                PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED){
        perror("mmap:");
        exit(1);
    }
    return 0;
}

/* olusturulan bellek alanina bilgiyi aktarır */
void dosyaya_yazma(char *msg) {
    time_t now = time(NULL);    // zaman bilgisinin nasil alinacagini bilmedigim icin gpt kullandim.
    char *formatted_time = ctime(&now);
    formatted_time[strlen(formatted_time) - 1] = '\0';
    char pid[MY_FILE_SIZE];
    sprintf(pid, "%d: %s  procces_id: %d parent_id: %d msg: %s\n", getpid(), formatted_time, getpid(), getppid(), msg);
    strncat(addr, pid, MY_FILE_SIZE - strlen(addr) - 1);
}

/* komutlarin islenmesini saglar */
void komut_alma(char *cmd) {
    char *args[INBUF_SIZE];
    int arg_count = 0;
    char *arg = strtok(cmd, " ");
    while (arg != NULL) {
        args[arg_count] = arg;
        arg = strtok(NULL, " ");
        arg_count++;
    }
    args[arg_count] = NULL;

    int pid = fork();
    if (pid == 0) {
        execvp(args[0], args);
        exit(0);
    }
    else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
    else {
        dosyaya_yazma("Fork failed");
    }
}

/* dosyaya yazilmis olan bilgilerin ciktisini verir */
void oku() {
    printf("Ayrilmis Bellekteki Bilgiler:\n%s", addr);
}

int main(int argc, char *argv[])
{
    initmem();
    dosyaya_yazma("M-shell basladi");
    char *inbuf = malloc(INBUF_SIZE);
    char *cmd = NULL;

    // burada "i" dongu sabitidir.
    int i;
    for (i = 0; i < 3; i++) {
        int pid = fork();
        if (pid == 0) {
            break; 
        }
        else if (pid < 0) {
            perror("multishell.c:fork");
            exit(1);
        }
    
    }

    while (1) {
        printf("Multishell %d $ ",i);
        fflush(stdout);
        fgets(inbuf, INBUF_SIZE, stdin);
        inbuf[strcspn(inbuf, "\n")] = '\0'; 
        cmd = strtok(inbuf, " ");

        if (strcmp(cmd, "exit") == 0) {
            dosyaya_yazma("Bitti");
            free(inbuf);
            munmap(addr, MY_FILE_SIZE);
            shm_unlink(MY_SHARED_FILE_NAME);
            close(fd);
            exit(0);
        }
        else if (strncmp(cmd, "oku", 3) == 0) {
            oku();
        }
        else if (strlen(cmd) > 0) {
            komut_alma(cmd);
            dosyaya_yazma(cmd);
        }
    }

        free(inbuf);
        munmap(addr, MY_FILE_SIZE);
        close(fd);

    }

