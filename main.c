#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>

#include "list.h"


struct arp_packet
{
    unsigned char ap_dstmac[6];  //6
    unsigned char ap_srcmac[6];  //6
    unsigned short ap_frame;     //2
    //arp
    unsigned short ap_hwtype;    //2
    unsigned short ap_prototype; //2
    unsigned char  ap_hwlen;     //1
    unsigned char  ap_prolen;    //1
    unsigned short ap_op;        //2
    unsigned char  ap_frommac[6];//6
    unsigned char  ap_fromip[4]; //4
    unsigned char  ap_tomac[6];  //6
    unsigned char  ap_toip[4];   //4

    unsigned char  ap_padding[18];	//18
};

typedef struct {
	pthread_t tid;
} t_data_t;


list_t * list_res;
pthread_mutex_t mutex;



int get_loacl_ip(uint8_t * ip, uint8_t * netmask, uint8_t * mac) {
	int fd;
	struct ifreq req;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(-1 == fd) {
		perror("socket: ");
		return 1;
	}

	bzero(&req, sizeof(struct ifreq));
	strcpy(req.ifr_ifrn.ifrn_name, "ens33");

	if(-1 == ioctl(fd, SIOCGIFADDR, &req)) {
		perror("SIOCGIFADDR: ");
		goto error;
	}
	memcpy(ip, req.ifr_ifru.ifru_addr.sa_data + 2, 4);

	if(-1 == ioctl(fd, SIOCGIFNETMASK, &req)) {
		perror("SIOCGIFNETMASK: ");
		goto error;
	}
	memcpy(netmask, req.ifr_ifru.ifru_netmask.sa_data + 2, 6);

	if(-1 == ioctl(fd, SIOCGIFHWADDR, &req)) {
		perror("SIOCGIFHWADDR: ");
		goto error;
	}
	memcpy(mac, req.ifr_ifru.ifru_hwaddr.sa_data, 6);

	close(fd);
	return 0;
error:
	close(fd);
	return 1;
}

int make_arp_packet(struct arp_packet * arp_in, uint8_t * ip_cli, uint8_t * ip_ser, uint8_t * mac_cli, uint16_t op)
{
	bzero(arp_in,sizeof(struct arp_packet));

	memset(arp_in->ap_dstmac, 0xFF, 6);
	memcpy(arp_in->ap_srcmac, mac_cli, 6);

	arp_in->ap_frame = htons(ETH_P_ARP);
	arp_in->ap_hwtype = htons(0x0001);
	arp_in->ap_prototype = htons(ETH_P_IP);
	arp_in->ap_hwlen = 6;
	arp_in->ap_prolen = 4;
	arp_in->ap_op = htons(op);			//0x0001-ARP req 0x0002-ARP Reply

	memcpy(arp_in->ap_frommac, mac_cli, 6);
	memcpy(arp_in->ap_fromip, ip_cli, 4);
	memcpy(arp_in->ap_toip, ip_ser, 4);

	return 0;
}

void * pthread_arp(void * pdata)
{
	int fd_socket;
	struct sockaddr_ll eth;
	socklen_t slen;
	struct timeval timeOut;
	int ret;
	struct arp_packet * arp_in, arp_rc;

	arp_in = (struct arp_packet *)pdata;

	fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(fd_socket < 0) {
		perror("socket: ");
		pthread_exit((void *)1);
	}

	// set socket timeout: 2s
	timeOut.tv_sec = 2;
	timeOut.tv_usec = 0;
	if(-1 == setsockopt(fd_socket, SOL_SOCKET, SO_RCVTIMEO, &timeOut, sizeof(struct timeval))) {
		perror("setsockopt: ");

		goto error;
	}

	// make sockaddr
	bzero(&eth, sizeof(struct sockaddr_ll));
	eth.sll_family = PF_PACKET;
	eth.sll_ifindex = if_nametoindex("ens33");

	// send ARP
	ret = sendto(fd_socket, arp_in, sizeof(struct arp_packet), 0, (struct sockaddr *)&eth, sizeof(struct sockaddr_ll));
	if(-1 == ret) {
		perror("send arp: ");

		goto error;
	}

	// recv ARP
again:
	slen = sizeof(struct sockaddr);
	bzero(&arp_rc, sizeof(struct arp_packet));
	ret = recvfrom(fd_socket, &arp_rc, sizeof(struct arp_packet), 0, (struct sockaddr *)&eth, &slen);
	if(-1 == ret) {
		goto error;
	}

	if(ntohs(arp_rc.ap_op) == 0x0002)
	{
		if(0 == memcmp(arp_in->ap_toip, arp_rc.ap_fromip, 4)) {
			char * buff = (char *)malloc(50);
			sprintf(buff, "%d.%d.%d.%d alive\n", arp_rc.ap_fromip[0], arp_rc.ap_fromip[1], arp_rc.ap_fromip[2], arp_rc.ap_fromip[3]);

			pthread_mutex_lock(&mutex);
			list_lpush(list_res, list_node_new(buff));
			pthread_mutex_unlock(&mutex);

			free(pdata);
			close(fd_socket);
			pthread_exit((void *)0);
		} else
			goto again;
	}

error:
	free(pdata);
	close(fd_socket);
	pthread_exit((void *)1);
}

int main(int argc, char * argv[])
{
	unsigned char ip_client[4];
	unsigned char mac_client[6];
	unsigned char netmask_client[4];
	unsigned char ip_ser[4];
	struct arp_packet * ptr_packet;
	uint32_t ip_n, netmask_n, ip_start_n, ip_stop_n;
	t_data_t * ptr_t_data;
	int i, ret;
	void * tret;

	list_t * list;
	list_iterator_t * it;
	list_node_t * node;

	list = list_new();
	list_res = list_new();

	pthread_mutex_init(&mutex, NULL);

	get_loacl_ip(ip_client, netmask_client, mac_client);
	printf("local ip: %d.%d.%d.%d\n", ip_client[0], ip_client[2], ip_client[3], ip_client[4]);
	printf("netmask: %d.%d.%d.%d\n", netmask_client[0], netmask_client[2], netmask_client[3], netmask_client[4]);
	printf("mac: 0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x\n\n", mac_client[0], mac_client[2], mac_client[3], mac_client[4],
			mac_client[5], mac_client[6]);

	ip_n = ntohl(*((uint32_t *)ip_client));
	netmask_n = ntohl(*((uint32_t *)netmask_client));

	ip_start_n = (ip_n & netmask_n) + 1;
	ip_stop_n = ((ip_n & netmask_n) | (~netmask_n));

	printf("start scan local ip...\n");
	while(1) {
		for(i = 0; i < 4; i++) {
			ip_ser[i] = (ip_start_n >> ((3 - i) * 8)) & 0xFF;
		}
		ptr_packet = (struct arp_packet *)malloc(sizeof(struct arp_packet));
		make_arp_packet(ptr_packet, ip_client, ip_ser, mac_client, 0x0001);

		ptr_t_data = (t_data_t *)malloc(sizeof(t_data_t));
		ret = pthread_create(&(ptr_t_data->tid), NULL, pthread_arp, ptr_packet);
		if(ret) {
			printf("create thread error\n");
			continue;
		}

		list_rpush(list, list_node_new(ptr_t_data));
		ip_start_n++;
		if(ip_start_n >= ip_stop_n)
			break;
	}

	// wait pthread exit
	it = list_iterator_new(list, LIST_HEAD);
	while((node = list_iterator_next(it))) {
		ptr_t_data = (t_data_t *)node->val;
		pthread_join(ptr_t_data->tid, &tret);
		free(ptr_t_data);
	}
	list_iterator_destroy(it);


	// show result
	printf("total: %d item\n", list_res->len);
	it = list_iterator_new(list_res, LIST_HEAD);
	while((node = list_iterator_next(it))) {
		printf("%s", (char *)node->val);
		free(node->val);
	}
	list_iterator_destroy(it);


	pthread_mutex_destroy(&mutex);
	list_destroy(list_res);
	list_destroy(list);
	return 0;
}






























