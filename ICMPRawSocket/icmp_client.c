#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h> /* memcpy, strlen */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

static unsigned short checksum ( const void * header, int length );

int main ( )
{
    // We create the socket
    int sock = socket ( AF_INET, SOCK_RAW, IPPROTO_ICMP );
    if ( sock < 0 )
    {
        printf ( "Error when creating socket.\n" );
        return -1;
    }

    // We set up desination info
    struct sockaddr_in destination;
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = inet_addr ( "127.0.0.1" );

    const char * msg = "Ceci est un message top secret.";
    size_t payload_size = strlen ( msg );
    size_t packet_length = sizeof ( struct icmphdr ) + payload_size;
    void * packet = malloc ( packet_length );

    struct icmphdr * icmp = packet;
    char * payload = ( packet + sizeof ( struct icmphdr ) );

    // We setup ICMP header
    icmp -> type = ICMP_ECHO;
    icmp -> code = 0;
    icmp -> un.echo.id = htons ( getpid ( ) );

    // We setup message
    // memset ( payload, 'd', payload_size );
    memcpy ( payload, msg, strlen ( msg ) );

	unsigned short i;
	for ( i = 0; i <= 1000 ; ++i )
	{
		// We set the sequence number
		icmp -> un.echo.sequence = htons ( i );

		// We compute ICMP checksum
		// icmp -> checksum = 0;
		icmp -> checksum = checksum ( packet, packet_length );

		// We send the ICMP packet
		int ret = sendto ( sock, packet, packet_length, 0, ( struct sockaddr * ) &destination, sizeof destination );

		printf ( "Nous avons envoyé %d octets.\n", ret );
		sleep ( 1 );
	}

    free ( packet );

    // We close the socket
    close ( sock );
    return 0;
}

/**
 * This allow us to automatically compute the IP & ICMP checksum.
 * Both, IP packets & ICMP packets have a checksum, but the algorithm
 * is the same for both!
 * WARNING: call me with the checksum field set to 0.
 *
 * @param header The header (IP or ICMP) you want to compute the checksum of
 * @param length The size of this header
 *
 * @return The IP or ICMP checksum
 */
static unsigned short checksum ( const void * header, int length )
{
    int sum = 0;
    const unsigned short * current = header;
    int remaining = length;

    while ( remaining > 1 )
    {
        sum += * current++;
        remaining -= 2;
    }

    if ( remaining == 1 )
    {
        sum += * current;
    }

    sum = ( sum >> 16 ) + ( sum & 0xffff );
    sum += ( sum >> 16 );
    return ( unsigned short ) ~sum;
}
