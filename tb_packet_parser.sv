/* Michael Mostytskyy
   Project: Packet Parser
   Description:
    Self-checking testbench for the IPv4/TCP/UDP Packet Parser.
    A monitor records every parser_done pulse (one per packet) and the
    directed tests compare ALL outputs against expected values:
    src/dst IP, src/dst port, is_tcp, is_udp, checksum_ok, parser_error.
    Directed scenarios:
    - Valid TCP / UDP / ICMP, corrupt checksum
    - Truncated Ethernet, IP and L4 regions
    - Non-IPv4 EtherType, bad IP version, bad IHL
    - IPv4 options (IHL=6)
    - Back-to-back frames (zero idle cycles), incl. recovery after an error
*/

`timescale 1ns / 1ps

module tb_packet_parser;

    // Signals
    logic        clk;
    logic        rst_n;
    logic [7:0]  data_in;
    logic        valid_in;
    logic        last_in;

    // DUT Outputs
    logic [31:0] src_ip;
    logic [31:0] dst_ip;
    logic [15:0] src_port;
    logic [15:0] dst_port;
    logic        is_tcp, is_udp;
    logic        checksum_ok;
    logic        parser_done, parser_error;

    // Global Buffer
    logic [7:0] packet_data [0:127];
    int         pkt_len;

    // DUT Instantiation
    packet_parser dut (.*);

    // Clock Generation
    always #5 clk = ~clk;

    // Simulation Variables
    int pass_cnt = 0;
    int fail_cnt = 0;

    // ------------------------------------------------------------------
    // Monitor: sample all outputs on every cycle where parser_done is high
    // ------------------------------------------------------------------
    logic [31:0] r_sip [0:63];
    logic [31:0] r_dip [0:63];
    logic [15:0] r_sp  [0:63];
    logic [15:0] r_dp  [0:63];
    logic        r_tcp [0:63];
    logic        r_udp [0:63];
    logic        r_csum[0:63];
    logic        r_err [0:63];
    int          n_res = 0;

    always @(posedge clk) begin
        if (rst_n && parser_done) begin
            r_sip[n_res]  = src_ip;
            r_dip[n_res]  = dst_ip;
            r_sp[n_res]   = src_port;
            r_dp[n_res]   = dst_port;
            r_tcp[n_res]  = is_tcp;
            r_udp[n_res]  = is_udp;
            r_csum[n_res] = checksum_ok;
            r_err[n_res]  = parser_error;
            n_res = n_res + 1;
        end
    end

    // ------------------------------------------------------------------
    // Build an Ethernet + IPv4 + 4-byte L4 ports + 8-byte payload frame
    //   ver/ihl are the two nibbles of the first IP byte.
    //   If ihl >= 5 the header is ihl*4 bytes (options = 0x01), else 20.
    // ------------------------------------------------------------------
    task automatic build_packet(
        input logic [31:0] s_ip, d_ip,
        input logic [7:0]  proto,
        input logic [15:0] s_port, d_port, eth_type,
        input logic        corrupt_chksum,
        input logic [3:0]  ver,
        input logic [3:0]  ihl
    );
        int i;
        int hb;
        logic [31:0] sum;
        logic [15:0] csum;

        hb = (ihl >= 5) ? (ihl * 4) : 20;

        for (i = 0; i < 128; i++) packet_data[i] = 0;

        // Ethernet Header
        for (i = 0; i < 12; i++) packet_data[i] = 8'hAA;
        packet_data[12] = eth_type[15:8];
        packet_data[13] = eth_type[7:0];

        // IP Header
        packet_data[14] = {ver, ihl};
        packet_data[15] = 8'h00;
        packet_data[16] = 8'h00;
        packet_data[17] = hb + 12;                 // total length
        packet_data[18] = 8'h00; packet_data[19] = 8'h01;
        packet_data[20] = 8'h00; packet_data[21] = 8'h00;
        packet_data[22] = 8'h40; packet_data[23] = proto;
        packet_data[24] = 8'h00; packet_data[25] = 8'h00;

        packet_data[26] = s_ip[31:24]; packet_data[27] = s_ip[23:16];
        packet_data[28] = s_ip[15:8];  packet_data[29] = s_ip[7:0];
        packet_data[30] = d_ip[31:24]; packet_data[31] = d_ip[23:16];
        packet_data[32] = d_ip[15:8];  packet_data[33] = d_ip[7:0];

        // IP options (only when hb > 20)
        for (i = 34; i < 14 + hb; i++) packet_data[i] = 8'h01;

        // Header checksum over the whole IP header
        sum = 0;
        for (i = 14; i < 14 + hb; i = i + 2)
            sum = sum + {packet_data[i], packet_data[i+1]};
        while (sum[31:16] != 0) sum = sum[15:0] + sum[31:16];
        csum = ~sum[15:0];
        if (corrupt_chksum) csum = csum + 1;

        packet_data[24] = csum[15:8];
        packet_data[25] = csum[7:0];

        // L4 Header (ports)
        packet_data[14 + hb + 0] = s_port[15:8];
        packet_data[14 + hb + 1] = s_port[7:0];
        packet_data[14 + hb + 2] = d_port[15:8];
        packet_data[14 + hb + 3] = d_port[7:0];

        // Payload
        for (i = 14 + hb + 4; i < 14 + hb + 12; i++) packet_data[i] = 8'hFF;

        pkt_len = 14 + hb + 12;
    endtask

    // ------------------------------------------------------------------
    // Drive the first `len` bytes of packet_data (last_in on the final byte).
    // valid_in is released afterwards; a following call in the same time
    // step overrides it, which gives true back-to-back frames.
    // ------------------------------------------------------------------
    task automatic send_frame(input int len);
        int n;
        for (n = 0; n < len; n++) begin
            valid_in <= 1;
            data_in  <= packet_data[n];
            last_in  <= (n == len - 1);
            @(posedge clk);
        end
        valid_in <= 0;
        last_in  <= 0;
    endtask

    // ------------------------------------------------------------------
    // Compare result number idx with the expected values
    // ------------------------------------------------------------------
    task automatic check_pkt(
        input string       name,
        input int          idx,
        input logic [31:0] e_sip, e_dip,
        input logic [15:0] e_sp, e_dp,
        input logic        e_tcp, e_udp, e_csum, e_err
    );
        logic ok;
        ok = 1;
        if (idx >= n_res) begin
            $error("FAIL: %s: no parser_done pulse received", name);
            fail_cnt++;
        end else begin
            if (r_sip[idx]  !== e_sip)  begin ok = 0; $display("  %s: src_ip  got %h exp %h", name, r_sip[idx],  e_sip);  end
            if (r_dip[idx]  !== e_dip)  begin ok = 0; $display("  %s: dst_ip  got %h exp %h", name, r_dip[idx],  e_dip);  end
            if (r_sp[idx]   !== e_sp)   begin ok = 0; $display("  %s: src_prt got %h exp %h", name, r_sp[idx],   e_sp);   end
            if (r_dp[idx]   !== e_dp)   begin ok = 0; $display("  %s: dst_prt got %h exp %h", name, r_dp[idx],   e_dp);   end
            if (r_tcp[idx]  !== e_tcp)  begin ok = 0; $display("  %s: is_tcp  got %b exp %b", name, r_tcp[idx],  e_tcp);  end
            if (r_udp[idx]  !== e_udp)  begin ok = 0; $display("  %s: is_udp  got %b exp %b", name, r_udp[idx],  e_udp);  end
            if (r_csum[idx] !== e_csum) begin ok = 0; $display("  %s: csum_ok got %b exp %b", name, r_csum[idx], e_csum); end
            if (r_err[idx]  !== e_err)  begin ok = 0; $display("  %s: p_error got %b exp %b", name, r_err[idx],  e_err);  end
            if (ok) begin
                $display("PASS: %s", name);
                pass_cnt++;
            end else begin
                $error("FAIL: %s", name);
                fail_cnt++;
            end
        end
    endtask

    // Watchdog
    initial begin
        #2000000;
        $error("FATAL: simulation watchdog expired");
        $finish;
    end

    // ------------------------------------------------------------------
    // Main Test Stimulus
    // ------------------------------------------------------------------
    initial begin
        $dumpfile("dump.vcd");
        $dumpvars(0, tb_packet_parser);

        // Init
        clk = 0; rst_n = 0; valid_in = 0; data_in = 0; last_in = 0;
        repeat (5) @(posedge clk);
        rst_n = 1;
        repeat (5) @(posedge clk);

        // 0. Valid TCP
        build_packet(32'hC0A80001, 32'hC0A80002, 8'h06, 16'h0080, 16'h0090, 16'h0800, 0, 4, 5);
        send_frame(pkt_len);
        repeat (5) @(posedge clk);

        // 1. Corrupt checksum
        build_packet(32'h11223344, 32'h55667788, 8'h06, 16'h0011, 16'h0022, 16'h0800, 1, 4, 5);
        send_frame(pkt_len);
        repeat (5) @(posedge clk);

        // 2. Truncated Ethernet header (10 bytes)
        build_packet(32'hF0F0F0F0, 32'hE0E0E0E0, 8'h06, 16'h0011, 16'h0022, 16'h0800, 0, 4, 5);
        send_frame(10);
        repeat (5) @(posedge clk);

        // 3. Truncated IP header (18 bytes), immediately followed by
        // 4. a valid TCP frame with zero idle cycles (error recovery)
        send_frame(18);
        build_packet(32'h0A000001, 32'h0A000002, 8'h06, 16'h1F90, 16'h0050, 16'h0800, 0, 4, 5);
        send_frame(pkt_len);
        repeat (5) @(posedge clk);

        // 5. Truncated L4 (IP header complete, only 2 port bytes)
        build_packet(32'h99887766, 32'h55443322, 8'h06, 16'h1234, 16'h5678, 16'h0800, 0, 4, 5);
        send_frame(36);
        repeat (5) @(posedge clk);

        // 6. ICMP (unsupported L4 protocol, valid IP header)
        build_packet(32'hAA000001, 32'hBB000002, 8'h01, 16'h0000, 16'h0000, 16'h0800, 0, 4, 5);
        send_frame(pkt_len);
        repeat (5) @(posedge clk);

        // 7. Valid UDP
        build_packet(32'hC0A80064, 32'hC0A80001, 8'h11, 16'h0035, 16'h1F90, 16'h0800, 0, 4, 5);
        send_frame(pkt_len);
        repeat (5) @(posedge clk);

        // 8. Non-IPv4 EtherType (IPv6), right after a valid packet
        build_packet(32'h12121212, 32'h34343434, 8'h06, 16'h0001, 16'h0002, 16'h86DD, 0, 4, 5);
        send_frame(pkt_len);
        repeat (5) @(posedge clk);

        // 9. Bad IP version (6)
        build_packet(32'h12121212, 32'h34343434, 8'h06, 16'h0001, 16'h0002, 16'h0800, 0, 6, 5);
        send_frame(pkt_len);
        repeat (5) @(posedge clk);

        // 10. Bad IHL (3)
        build_packet(32'h12121212, 32'h34343434, 8'h06, 16'h0001, 16'h0002, 16'h0800, 0, 4, 3);
        send_frame(pkt_len);
        repeat (5) @(posedge clk);

        // 11. IPv4 with options (IHL = 6 -> 24-byte header), TCP
        build_packet(32'h0B0B0B0B, 32'h0C0C0C0C, 8'h06, 16'h1234, 16'h5678, 16'h0800, 0, 4, 6);
        send_frame(pkt_len);
        repeat (5) @(posedge clk);

        // 12/13. Two valid frames back-to-back (TCP then UDP), no idle cycle
        build_packet(32'h01020304, 32'h05060708, 8'h06, 16'h0100, 16'h0200, 16'h0800, 0, 4, 5);
        send_frame(pkt_len);
        build_packet(32'h0A0B0C0D, 32'h0E0F1011, 8'h11, 16'h0300, 16'h0400, 16'h0800, 0, 4, 5);
        send_frame(pkt_len);
        repeat (10) @(posedge clk);

        // --------------------------------------------------------------
        // Checks:      name, idx, src_ip, dst_ip, src_p, dst_p, tcp,udp,csum,err
        // --------------------------------------------------------------
        check_pkt("Valid TCP",                  0, 32'hC0A80001, 32'hC0A80002, 16'h0080, 16'h0090, 1,0,1,0);
        check_pkt("Corrupt Checksum",           1, 32'h11223344, 32'h55667788, 16'h0011, 16'h0022, 1,0,0,0);
        check_pkt("Truncated Ethernet",         2, 32'h0,        32'h0,        16'h0,    16'h0,    0,0,0,1);
        check_pkt("Truncated IP",               3, 32'h0,        32'h0,        16'h0,    16'h0,    0,0,0,1);
        check_pkt("Valid TCP after error (b2b)",4, 32'h0A000001, 32'h0A000002, 16'h1F90, 16'h0050, 1,0,1,0);
        check_pkt("Truncated L4",               5, 32'h99887766, 32'h55443322, 16'h1234, 16'h0000, 1,0,0,1);
        check_pkt("ICMP (no TCP/UDP flag)",     6, 32'hAA000001, 32'hBB000002, 16'h0,    16'h0,    0,0,1,0);
        check_pkt("Valid UDP",                  7, 32'hC0A80064, 32'hC0A80001, 16'h0035, 16'h1F90, 0,1,1,0);
        check_pkt("Non-IPv4 EtherType",         8, 32'h0,        32'h0,        16'h0,    16'h0,    0,0,0,0);
        check_pkt("Bad IP version",             9, 32'h0,        32'h0,        16'h0,    16'h0,    0,0,0,1);
        check_pkt("Bad IHL",                   10, 32'h0,        32'h0,        16'h0,    16'h0,    0,0,0,1);
        check_pkt("IPv4 options (IHL=6) TCP",  11, 32'h0B0B0B0B, 32'h0C0C0C0C, 16'h1234, 16'h5678, 1,0,1,0);
        check_pkt("Back-to-back #1 TCP",       12, 32'h01020304, 32'h05060708, 16'h0100, 16'h0200, 1,0,1,0);
        check_pkt("Back-to-back #2 UDP",       13, 32'h0A0B0C0D, 32'h0E0F1011, 16'h0300, 16'h0400, 0,1,1,0);

        // Exactly one parser_done pulse per packet
        if (n_res == 14) begin
            $display("PASS: exactly one parser_done pulse per packet (%0d)", n_res);
            pass_cnt++;
        end else begin
            $error("FAIL: expected 14 parser_done pulses, got %0d", n_res);
            fail_cnt++;
        end

        // Summary
        $display("");
        $display("FINAL RESULTS: Pass=%0d, Fail=%0d", pass_cnt, fail_cnt);
        if (fail_cnt == 0) $display("TEST PASSED");
        else               $display("TEST FAILED");
        $display("");
        $finish;
    end
endmodule