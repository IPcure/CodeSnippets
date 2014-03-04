#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

static unsigned short checksum ( const void * header, int length );
static int toggle_kernel_auto_icmp_reply ( int yes );

int main ( )
{
    if ( getuid ( ) != 0 )
    {
        printf ( "Please launch me as root.\n" );
        return -1;
    }

    int auto_icmp_disabled = 0;

    if ( toggle_kernel_auto_icmp_reply ( 0 ) )
    {
        printf ( "Kernel auto ICMP replies sucessfully disabled.\n" );
        int auto_icmp_disabled = 1;
    }
    else
    {
        printf ( "Unable to disable kernel auto ICMP replies. It doesn't matter. Maybe you are on a Mac, and don't have a '/proc' partition.\n" );
    }

    // We create the socket
    int sock = socket ( AF_INET, SOCK_RAW, IPPROTO_ICMP );
    if ( sock < 0 )
    {
        printf ( "Error when creating socket.\n" );
        return -1;
    }

    // We set up source info (who is talking to us?)
    struct sockaddr_in source;
    socklen_t source_length = sizeof ( source );

    // We prepare memory for receiving packets
    size_t payload_size = 65500;
    size_t packet_size = sizeof ( struct iphdr ) + sizeof ( struct icmphdr ) + payload_size;
    void * packet = malloc ( packet_size );
    struct iphdr * packet_iphdr = packet;
    struct icmphdr * packet_icmphdr = ( packet + sizeof ( struct iphdr ) );
    char * packet_payload = ( packet + sizeof ( struct iphdr ) + sizeof ( struct icmphdr ) );

	printf ( "Waiting for someone to give me an ICMP packet. :)\n" );

    // We receive!
    for ( ; ; )
    {
        int ret = recvfrom ( sock, packet, packet_size, 0, ( struct sockaddr * ) &source, &source_length );

		// Convert source IP to understandable char *.
        char * source_ip = inet_ntoa ( source.sin_addr );

        switch ( packet_icmphdr -> type )
        {
            case ICMP_ECHO:
                printf ( "Echo request" );
                break;

            case ICMP_ECHOREPLY:
                printf ( "Echo reply" );
                break;

            default:
                printf ( "Unknown" );
        }

		// We display ICMP header info, as well as who is talking to us
        int payload_size = ret - sizeof ( struct iphdr ) - sizeof ( struct icmphdr );
        printf ( " from %s (%d/%d octets)", source_ip, payload_size, ret );
        printf ( " ID = %#06x, SEQ = %d/%d\n",
				ntohs ( packet_icmphdr -> un.echo.id ),
				ntohs ( packet_icmphdr -> un.echo.sequence ),
				packet_icmphdr -> un.echo.sequence );

		// We display a byte index
        int i;
        for ( i = 1 ; i <= payload_size ; ++i )
        {
            printf ( "%2d ", i );
        }
        printf ( "\n" );

		// We display the bytes values in hexa
        unsigned char * current = packet_payload;
        for ( i = 0 ; i < payload_size ; ++i, ++current )
        {
            printf ( "%02x ", * current );
        }
        printf ( "\n" );

		// We display the bytes values in ASCII
        current = packet_payload;
        for ( i = 0 ; i < payload_size ; ++i )
        {
            printf ( "%2c ", * current++ );
        }
        printf ( "\n\n" );
    }

    free ( packet );

    // We close the socket
    close ( sock );

    if ( auto_icmp_disabled == 1 )
    {
        if ( toggle_kernel_auto_icmp_reply ( 1 ) )
        {
            printf ( "Kernel auto ICMP replies sucessfully re-enabled.\n" );
        }
        else
        {
            printf ( "Unable to re-enable kernel auto ICMP replies. It doesn't matter. Maybe you are on a Mac, and don't have a '/proc' partition.\n" );
        }
    }
    return 0;
}

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

static int toggle_kernel_auto_icmp_reply ( int yes )
{
    int fd = open ( "/proc/sys/net/ipv4/icmp_echo_ignore_all", O_WRONLY );
    if ( fd == -1 )
    {
        return 0;
    }

    int res = write ( fd,  ( yes == 1 ? "0" : "1" ), 1 );
    close ( fd );

    if ( res == -1 )
    {
        return 0;
    }

    return 1;
}
