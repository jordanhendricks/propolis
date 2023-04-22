#!/usr/sbin/dtrace -s

#pragma D option defaultargs

/*
 *
 * clients -> ws_recv
 *
 *
 * close_recv: close websocket clients and exit task
 * new_ws_recv: new client
 * uart_write: ws input bytes (cur_input set)
 * ws_send: cur_output unset
 * uart_read: cur_output set
 * recv_ch_fut: cur_input set if it is a Binary message; remove the connection
 * if it is a Close
 * ws_recv: ??????? does nothing?????
 *
 */


dtrace:::BEGIN
{
	if ($$1 == "") {
		printf("ERROR: propolis-server pid required\n");
		exit(1);
	}

	printf("tracing live migration protocol times for pid %d...\n", $1);
	printf("\n");

	if ($$2 == "v") {
		printf("%-12s %-10s %30s\n", "PHASE", "", "TIMESTAMP");
	}
}

propolis$1:::serial_close_recv
{
	printf("[closing all connections; exiting task\n");
}

propolis$1:::serial_new_ws
{
	printf("[new ws connection]\n");
}

propolis$1:::serial_uart_write
{
	printf("[client wrote %d bytes to UART device]\n", args[0]);
}

propolis$1:::serial_uart_out
{
	printf("[output bytes sent]\n");
}

propolis$1:::serial_uart_read {}
{
	printf("[read %d bytes from UART device]\n", args[0]);
}


propolis$1:::serial_inject_uart {}
{
	printf("[inject ???? ]\n");
}

propolis$1:::serial_ws_recv { }
