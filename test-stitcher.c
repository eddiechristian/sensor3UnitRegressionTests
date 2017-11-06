/**
 * Simple application to load test Iron-stitch by constantly throwing fake
 * suricata JSON output to it. Capable of writing over 100k messages per second
 */

 /**
  * perf stat -B dd if=/dev/zero of=/dev/null count=1000000
  */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#define MAX_UNIX_DGRAM_SIZE      130688
/*  -----------------   */

struct timespec G_counter_time = {0, 0};
uint64_t G_counter_val_last = 0;
uint64_t G_counter_val = 0;
uint64_t G_counter_accum = 0;
uint64_t G_counter_accum_pts = 0;

void UpdateMessageCounter(void) {
struct timespec curtime;
  int res = clock_gettime(CLOCK_REALTIME, &curtime);
  if(res != 0){
    perror("failed to get time");
    return;
  }

  ++G_counter_val;
  if(G_counter_time.tv_sec != curtime.tv_sec){
    if(G_counter_time.tv_sec != 0){
      uint64_t val = (G_counter_val - G_counter_val_last) / (curtime.tv_sec - G_counter_time.tv_sec);
      G_counter_accum += val;
      G_counter_accum_pts += 1;
      printf(" Messages Processed Total:%llu                Last:%llu                Average:%llu\n", G_counter_val, val, G_counter_accum / G_counter_accum_pts);
    }
    G_counter_time = curtime;
    G_counter_val_last = G_counter_val;
  }

}

void usage() {
  printf("Usage:");
  printf("\tParams");
}

int
main(int argc, char** argv)
{
  int ret;
  int sck;
  int c;

  char* sock_name = NULL;

  while ((c = getopt (argc, argv, "t:")) != -1)
   switch (c)
   {
          case 't':
                  sock_name = optarg;
          break;
   }

  if (!sock_name) {
          usage();
          exit(-1);
  }

  struct sockaddr_un addr;
  /* create socket */
  sck = socket(PF_UNIX, SOCK_DGRAM, 0);
  if (sck == -1) {
    printf("Can not create socket: %s\n", strerror(errno));
    exit(-1);
  }

  FILE* file = fopen("./eve.json", "r");
  if (!file) {
      printf("could not open ./eve.json\n");
      exit(-2);
  }

  char line[MAX_UNIX_DGRAM_SIZE];

  /* set address */
  addr.sun_family = AF_UNIX;

  strncpy(addr.sun_path, sock_name, strlen(sock_name)+1);

  /* Connect to unix socket */
  ret = connect(sck, (struct sockaddr *) &addr, SUN_LEN(&addr));
  if (ret == -1) {
    printf("Can not connect: %s\n", strerror(errno));
    exit(-3);
  }

  struct pollfd poll_set;
  poll_set.fd = sck;
  poll_set.events = POLLOUT;

  poll_set.revents = 0;

  int poll_ret = poll(&poll_set, 1, 1000);
  if(poll_ret > 0){
    if(poll_set.revents & POLLOUT){
      while (fgets(line, sizeof(line), file)) {
          ret = send(sck, line, strlen(line), 0);
        if(ret == -1){
          if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK){
            perror("send");
            exit(errno);
          }
        }
        UpdateMessageCounter();
      }
    }
  }

  fclose(file);
  return 0;
}
