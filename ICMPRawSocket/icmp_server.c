#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

static void __attribute__ ( ( noreturn ) ) server ( );
static int toggle_kernel_auto_icmp_reply ( int yes );
static void sigIntHandler ( int sig );

static void * packet = 0;
static int sock = -1;
static int auto_icmp_disabled = 0;

int main ( )
{
    // We want to catch SIGINT (Ctrl + C) to exit properly.
    struct sigaction act;
    memset ( &act, 0, sizeof ( act ) );
    act.sa_handler = sigIntHandler;
    sigaction ( SIGINT, &act, 0 );


    if ( getuid ( ) != 0 )
    {
        printf ( "Please launch me as root.\n" );
        return -1;
    }

    if ( toggle_kernel_auto_icmp_reply ( 0 ) )
    {
        printf ( "Kernel auto ICMP replies sucessfully disabled.\n" );
        auto_icmp_disabled = 1;
    }
    else
    {
        printf ( "Unable to disable kernel auto ICMP replies. It doesn't matter. Maybe you are on a Mac, and don't have a '/proc' partition.\n" );
    }

    server ( );

    return 0;
}

/**
 * This is the infinite loop, the listening ICMP server. :)
 */
static void server ( )
{
    // We create the socket
    sock = socket ( AF_INET, SOCK_RAW, IPPROTO_ICMP );
    if ( sock < 0 )
    {
        printf ( "Error when creating socket.\n" );
        ( void ) ( * sigIntHandler ) ( SIGINT );
    }

    // We set up source info (who is talking to us?)
    struct sockaddr_in source;
    socklen_t source_length = sizeof ( source );

    // We prepare memory for receiving packets
    size_t payload_size = 65500;
    size_t packet_size = sizeof ( struct iphdr ) + sizeof ( struct icmphdr ) + payload_size;
    packet = malloc ( packet_size );
    // struct iphdr * packet_iphdr = packet;
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
                printf ( "Another ICMP type" );
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

		// We display the byte values in hexa
        char * current = packet_payload;
        for ( i = 0 ; i < payload_size ; ++i, ++current )
        {
            printf ( "%02x ", * current );
        }
        printf ( "\n" );

		// We display the byte values in ASCII
        current = packet_payload;
        for ( i = 0 ; i < payload_size ; ++i )
        {
            printf ( "%2c ", * current++ );
        }
        printf ( "\n\n" );
    }
}

/**
 * The Linux kernel automatically answers all ICMP Echo Request.
 * It generates ICMP Echo Replies. This is not a wanted behaviour
 * for our application, since we want to generate answers ourselves.
 * We therefore ask the kernel to unable its automatic replies.
 *
 * @param yes Whether to enable ( 1 ) or disable ( 0 ) kernel ICMP replies
 *
 * @return 1 if successful, 0 otherwise.
 */
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

/**
 * A SIGINT handler.
 * The server is an infinite loop, so the only way to exit is Ctrl+C.
 * We want to catch SIGINT to free ressources and exit properly.
 */
static void sigIntHandler ( int sig )
{
    if ( sig != SIGINT )
    {
        return;
    }

    if ( packet != 0 )
    {
        free ( packet );
    }

    // We close the socket
    if ( sock != -1 )
    {
        close ( sock );
    }

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

    exit ( EXIT_SUCCESS );
}
