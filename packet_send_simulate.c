#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <unistd.h>

#define MAX_FILENAME_SIZE (256)

pcap_t *handler = NULL;
static unsigned char *buffer = NULL;
static long buffer_len = 0;

void 
usage(char *pname)
{
    if (NULL != pname)
    {
        printf("usage: %s -f <filename>\n", pname);
    }
}

void packet_send(void)
{
    if (handler)
    {
        pcap_sendpacket(handler, buffer, buffer_len);
    }
}

int transfer(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0;
}

int main(int argc, char *argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    uint8_t tmp[6] = {0};
    int opt;
    int ret = 0;
    char filename[MAX_FILENAME_SIZE] = {0};
    long curpos;
    char *raw = NULL;

    while ((opt = getopt(argc, argv, "hf:")) != -1)
    {
        switch (opt)
        {
            case 'h':
                usage(argv[0]);
                return 0;
            case 'f':
                printf("%s\n", optarg);
                strcpy(filename, optarg);
                break;
            default:
                break;
        }
    }

    if (0 == strlen(filename))
    {
        fprintf(stderr, "should provide filename\n");
        return -1;
    }
    FILE *fp = fopen(filename, "r");
    if (NULL == fp)
    {
        fprintf(stderr, "fopen fail\n");
        return -1;
    }

    curpos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    buffer_len = ftell(fp);
    fseek(fp, curpos, SEEK_SET);
    raw = malloc(buffer_len);
    buffer = malloc(buffer_len / 2);
    memset(raw, 0, buffer_len);
    memset(buffer, 0, buffer_len / 2);
    fread(raw, 1, buffer_len, fp);
    for (int i = 0; i < buffer_len / 2; i++)
        buffer[i] = (transfer(raw[i * 2]) << 4) | transfer(raw[i * 2 + 1]);
    free(raw);
    buffer_len = buffer_len / 2;
    printf("buffer size:%ld\n", buffer_len);
    fclose(fp);
    
    dev = pcap_lookupdev(errbuf);
    if (NULL == dev)
    {
        fprintf(stderr,"could not find default device:%s\n", errbuf);
        return -1;
    }
    printf("device:%s\n",dev);

    bpf_u_int32 mask;
    bpf_u_int32 net;
    if (-1 == pcap_lookupnet(dev, &net, &mask, errbuf))
    {
        fprintf(stderr, "counld not get netmask for device %s;%s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    handler = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf);

    if (NULL == handler)
    {
        fprintf(stderr,"could not open device %s;%s",dev,errbuf);
        ret = -2;
        goto out;
    }

    packet_send();
out:
    if (NULL != buffer)
        free(buffer);
    pcap_close(handler);
    return ret;
}

