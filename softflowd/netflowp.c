/* $Id$ */

#include "common.h"
#include "log.h"
#include "treetype.h"
#include "softflowd.h"

RCSID("$Id$");

static const char *
format_time(time_t t)
{
        struct tm *tm;
        static char buf[32];

        tm = gmtime(&t);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);

        return (buf);

}


/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */

int
timeval_subtract (result, x, y)
     struct timeval *result, *x, *y;
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

# define timersub(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)


/*
 * Given an array of expired flows,print the flows 
 * Returns number of packets sent or -1 on error
 */
int
print_netflow(struct FLOW **flows, int num_flows, int fd, u_int16_t ifidx,
    u_int64_t *flows_exported, struct timeval *system_boot_time,
    int verbose_flag)
{
	struct timeval now;
	struct timeval tdiff;
	u_int32_t uptime_ms;
	int i;
	char buffer[250], sip[20], dip[20], sflag[2][7], stime[15], etime[15];
	
	gettimeofday(&now, NULL);
	uptime_ms = timeval_sub_ms(&now, system_boot_time);

	for (i = 0; i < num_flows; i++) {

		/* we support only IPv4*/
		if (flows[i]->af != AF_INET)
			continue;
		if(flows[i]->protocol == 17 || flows[i]->protocol == 6){		

			char stime[32], ftime[32];
		        snprintf(stime, sizeof(stime), "%s", format_time(flows[i]->flow_start.tv_sec)); 
			snprintf(ftime, sizeof(ftime), "%s", format_time(flows[i]->flow_last.tv_sec));

//			printf("%s.%03ld\t",stime, (flows[i]->flow_start.tv_usec + 500) / 1000);
//			printf("%s.%03ld\t",ftime, (flows[i]->flow_last.tv_usec + 500) / 1000);
/*			printf("%ld.%d\t", flows[i]->flow_start.tv_sec, (int)((flows[i]->flow_start.tv_usec+500)/1000));
                        printf("%ld.%d\t", flows[i]->flow_last.tv_sec, (int)((flows[i]->flow_last.tv_usec+500)/1000));
			printf("%d\t", timeval_sub_ms(&(flows[i]->flow_last), &(flows[i]->flow_start)));
			printf("%s\t", (flows[i]->protocol==6)?"TCP":"UDP");
	                printf("%s\t%hu\t", inet_ntoa(flows[i]->addr[flows[i]->flow_dir].v4), ntohs(flows[i]->port[flows[i]->flow_dir]));
	                printf("%s\t%hu\t", inet_ntoa(flows[i]->addr[(flows[i]->flow_dir) ^ 1].v4), ntohs(flows[i]->port[(flows[i]->flow_dir)^1]));
			printf("%02x\t", flows[i]->tcp_flags[1]|flows[i]->tcp_flags[0]);
			printf("%u\t", ((flows[i]->packets[1])+(flows[i]->packets[0])));
	                printf("%u\t", ((flows[i]->octets[1])+(flows[i]->octets[0])));
			printf("%d\t", ((flows[i]->octets[1] > 0)&& (flows[i]->octets[1]>0))?2:1);
			printf("\n");
*/
			snprintf(sip, sizeof(sip), "%s", inet_ntoa(flows[i]->addr[flows[i]->flow_dir].v4));
			snprintf(dip, sizeof(dip), "%s", inet_ntoa(flows[i]->addr[(flows[i]->flow_dir) ^ 1].v4));

        if ( flows[i]->tcp_flags[0] > 63 ) {
                snprintf(sflag[0], 7, "0x%02x", flows[i]->tcp_flags[0]);
        } else {
                sflag[0][0] = flows[i]->tcp_flags[0] & 32 ? 'U' : '.';
                sflag[0][1] = flows[i]->tcp_flags[0] & 16 ? 'A' : '.';
                sflag[0][2] = flows[i]->tcp_flags[0] &  8 ? 'P' : '.';
                sflag[0][3] = flows[i]->tcp_flags[0] &  4 ? 'R' : '.';
                sflag[0][4] = flows[i]->tcp_flags[0] &  2 ? 'S' : '.';
                sflag[0][5] = flows[i]->tcp_flags[0] &  1 ? 'F' : '.';
        }
        sflag[0][6] = '\0';

        if ( flows[i]->tcp_flags[1] > 63 ) {
                snprintf(sflag[1], 7, "0x%02x", flows[i]->tcp_flags[1]);
        } else {
                sflag[1][0] = flows[i]->tcp_flags[1] & 32 ? 'U' : '.';
                sflag[1][1] = flows[i]->tcp_flags[1] & 16 ? 'A' : '.';
                sflag[1][2] = flows[i]->tcp_flags[1] &  8 ? 'P' : '.';
                sflag[1][3] = flows[i]->tcp_flags[1] &  4 ? 'R' : '.';
                sflag[1][4] = flows[i]->tcp_flags[1] &  2 ? 'S' : '.';
                sflag[1][5] = flows[i]->tcp_flags[1] &  1 ? 'F' : '.';
        }
        sflag[1][6] = '\0';

			//timeval_subtract(&tdiff, &(flows[i]->flow_last), &(flows[i]->flow_start));
			timersub(&(flows[i]->flow_last), &(flows[i]->flow_start), &(tdiff));
			snprintf(buffer, sizeof(buffer), "%ld.%d\t%ld.%d\t%ld.%d\t%s\t%s\t%hu\t%s\t%hu\t%s\t%s\t%u\t%u\t%d\t\n",
	                        flows[i]->flow_start.tv_sec, (int)((flows[i]->flow_start.tv_usec+500)/1000),
	                        flows[i]->flow_last.tv_sec, (int)((flows[i]->flow_last.tv_usec+500)/1000),
				tdiff.tv_sec, (int)((tdiff.tv_usec + 500)/1000),
	                        (flows[i]->protocol==6)?"TCP":"UDP",
	                        sip, ntohs(flows[i]->port[flows[i]->flow_dir]),
	                       	dip, ntohs(flows[i]->port[(flows[i]->flow_dir)^1]),
				sflag[flows[i]->flow_dir], sflag[(flows[i]->flow_dir)^1],
	                        ((flows[i]->packets[1])+(flows[i]->packets[0])),
	                        ((flows[i]->octets[1])+(flows[i]->octets[0])),
	                        ((flows[i]->octets[1] > 0)&& (flows[i]->octets[1]>0))?2:1);
                        
//			printf("%s %s,\n%s", stime, ftime, buffer);
			if(write(fd, buffer, strlen(buffer))==-1) {
				perror("Error in writing to output file");
			}
			*flows_exported+=(((flows[i]->octets[1] > 0)&& (flows[i]->octets[1]>0))?2:1);
					
		}

	}

	*flows_exported += num_flows;
	
	return (1);
}

