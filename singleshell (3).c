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
    fd = shm_open(MY_SHARED_FILE_NAME, O_RDWR, 0);
    if (fd < 0){
        perror("singleshell.c:fd:line31");
        exit(1);
    }
    addr = mmap(NULL, MY_FILE_SIZE,
                PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == NULL){
        perror("singleshell.c:mmap:");
        close(fd);
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
    sprintf(pid, "%d: %s %s\n", getpid(), formatted_time, msg);
    strncat(addr, pid, MY_FILE_SIZE - strlen(addr) - 1);
}
/* komutlarin islenmesini saglar */
void komut_alma(char *cmd) {
    char *args[INBUF_SIZE];
    int sayıcı = 0; //bosluklara gore arguman sayısını toplar
    char *arg = strtok(cmd, " ");
    while (arg != NULL) {
        args[sayıcı] = arg;
        arg = strtok(NULL, " ");
        sayıcı++;
    }
    args[sayıcı] = NULL;

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
    dosyaya_yazma("Basladi");
    char *inbuf = malloc(INBUF_SIZE);
    char *cmd = NULL;

while (1) {
    write(1,"$",2);
    fflush(stdout);
    fgets(inbuf, INBUF_SIZE, stdin);
    inbuf[strcspn(inbuf, "\n")] = '\0'; 
    cmd = strtok(inbuf, " ");

    if (cmd == NULL) {
            continue;
    }
    if (strcmp(cmd, "exit") == 0) {
        dosyaya_yazma("Bitti");
        free(inbuf);
        munmap(addr, MY_FILE_SIZE);
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

    munmap(addr, MY_FILE_SIZE);
    close(fd);
}
