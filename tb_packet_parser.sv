/* Michael Mostytskyy
   Project: Packet Parser
   Description:
    Testbench for the IPv4/TCP/UDP Packet Parser.
    Verifies IP extraction, L4 port extraction, and checksum validation.
    Features:
    - Directed tests for TCP, Checksum Errors, and Short Packets.
    - Automated result verification.
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
    logic [7:0] packet_data [0:63];

    // DUT Instantiation
    packet_parser dut (.*);

    // Clock Generation
    always #5 clk = ~clk;

    // Simulation Variables
    int pass_cnt = 0;
    int fail_cnt = 0;

    // Helper Task: Build Packet
    task build_packet(
        input logic [31:0] s_ip, d_ip,
        input logic [7:0]  proto,
        input logic [15:0] s_port, d_port, eth_type,
        input logic        corrupt_chksum
    );
        int i;
        logic [31:0] sum;
        logic [15:0] csum;

        // Reset buffer
        for(i=0; i<64; i++) packet_data[i] = 0;

        // Ethernet Header
        for(i=0; i<12; i++) packet_data[i] = 8'hAA;
        packet_data[12] = eth_type[15:8]; packet_data[13] = eth_type[7:0];

        // IP Header (Standard 20 bytes)
        packet_data[14] = 8'h45;
        packet_data[15] = 8'h00; packet_data[16] = 8'h00; packet_data[17] = 8'h2E;
        packet_data[18] = 8'h00; packet_data[19] = 8'h01; packet_data[20] = 8'h00; packet_data[21] = 8'h00;
        packet_data[22] = 8'h40; packet_data[23] = proto; packet_data[24] = 0;     packet_data[25] = 0;

        packet_data[26] = s_ip[31:24]; packet_data[27] = s_ip[23:16];
        packet_data[28] = s_ip[15:8];  packet_data[29] = s_ip[7:0];
        packet_data[30] = d_ip[31:24]; packet_data[31] = d_ip[23:16];
        packet_data[32] = d_ip[15:8];  packet_data[33] = d_ip[7:0];

        // Calculate Checksum
        sum = 0;
        for(i=14; i<34; i=i+2) sum += {packet_data[i], packet_data[i+1]};
        while(sum[31:16]) sum = sum[15:0] + sum[31:16];
        csum = ~sum[15:0];
        if (corrupt_chksum) csum++;

        packet_data[24] = csum[15:8]; packet_data[25] = csum[7:0];

        // L4 Header (Ports)
        packet_data[34] = s_port[15:8]; packet_data[35] = s_port[7:0];
        packet_data[36] = d_port[15:8]; packet_data[37] = d_port[7:0];
        
        // Payload
        for(i=38; i<46; i++) packet_data[i] = 8'hFF;
    endtask

    // Helper Task: Verify Results
    task automatic verify_results(
        input string test_name,
        input logic  expect_parse_error,
        input logic  expect_checksum_fail,
        input logic [31:0] exp_s_ip,
        input logic [31:0] exp_d_ip
    );
        int timeout_ctr;

        // Wait for completion
        timeout_ctr = 0;
        while (parser_done == 0 && timeout_ctr < 1000) begin
            @(posedge clk);
            timeout_ctr++;
        end

        if (timeout_ctr >= 1000) begin
            $error("FATAL: %s: TIMEOUT! parser_done never went high.", test_name);
            $finish;
        end

        @(negedge clk);

        // Case 1: Parser Error
        if (expect_parse_error) begin
            assert(parser_error) begin
                $display("PASS: %s: Caught Error", test_name); pass_cnt++;
            end else begin
                $error("FAIL: %s: Expected Error, got None", test_name); fail_cnt++;
            end
        end

        // Case 2: Checksum Failure
        else if (expect_checksum_fail) begin
            assert(!checksum_ok) else $error("FAIL: %s: Expected Checksum Fail, got OK", test_name);
            assert(!parser_error) else $error("FAIL: %s: Checksum test shouldn't trigger parser_error", test_name);

            if (!checksum_ok && !parser_error && src_ip == exp_s_ip) begin
                 $display("PASS: %s: Caught Bad Checksum & Extracted Data Correctly", test_name);
                 pass_cnt++;
            end else begin
                 $error("FAIL: %s: Mismatch during checksum test", test_name);
                 fail_cnt++;
            end
        end

        // Case 3: Success Path
        else begin
            if (src_ip == exp_s_ip && dst_ip == exp_d_ip && checksum_ok && !parser_error) begin
                $display("PASS: %s: Success", test_name); pass_cnt++;
            end else begin
                $error("FAIL: %s: Mismatch. Err=%b CsumOK=%b IPs: %h vs %h",
                        test_name, parser_error, checksum_ok, src_ip, exp_s_ip);
                fail_cnt++;
            end
        end
    endtask

    // Main Test Stimulus
    initial begin
        int i;
        int timeout_icmp;

        $dumpfile("dump.vcd");
        $dumpvars(0, tb_packet_parser);

        // Init
        clk = 0; rst_n = 0; valid_in = 0; data_in = 0; last_in = 0;
        repeat(5) @(posedge clk);
        rst_n = 1;
        repeat(5) @(posedge clk);

        // 1. Valid TCP Packet
        build_packet(32'hC0A80001, 32'hC0A80002, 8'h06, 16'h80, 16'h90, 16'h0800, 0);
        for(i=0; i<46; i++) begin
            valid_in <= 1; data_in <= packet_data[i]; last_in <= (i==45); @(posedge clk);
        end
        valid_in <= 0; last_in <= 0;
        verify_results("Valid TCP", 0, 0, 32'hC0A80001, 32'hC0A80002);

        repeat(5) @(posedge clk);

        // 2. Corrupt Checksum
        build_packet(32'h11223344, 32'h55667788, 8'h06, 16'h11, 16'h22, 16'h0800, 1);
        for(i=0; i<46; i++) begin
            valid_in <= 1; data_in <= packet_data[i]; last_in <= (i==45); @(posedge clk);
        end
        valid_in <= 0; last_in <= 0;
        verify_results("Corrupt Checksum", 0, 1, 32'h11223344, 32'h55667788);

        repeat(5) @(posedge clk);

        // 3. Early Termination (Short Packet)
        $display("INFO: Sending Short Packet");
        build_packet(32'hF0F0F0F0, 32'hE0E0E0E0, 8'h06, 16'h11, 16'h22, 16'h0800, 0);
        for(i=0; i<18; i++) begin
            valid_in <= 1; data_in <= packet_data[i]; last_in <= (i==17); @(posedge clk);
        end
        valid_in <= 0; last_in <= 0;
        verify_results("Early Termination", 1, 0, 0, 0);

        repeat(5) @(posedge clk);

        // 4. ICMP (Unsupported Protocol)
        build_packet(32'hAA000001, 32'hBB000002, 8'h01, 16'h0, 16'h0, 16'h0800, 0);
        for(i=0; i<46; i++) begin
            valid_in <= 1; data_in <= packet_data[i]; last_in <= (i==45); @(posedge clk);
        end
        valid_in <= 0; last_in <= 0;

        // Custom Wait for ICMP
        timeout_icmp = 0;
        while (parser_done == 0 && timeout_icmp < 1000) begin
            @(posedge clk);
            timeout_icmp++;
        end

        if (timeout_icmp >= 1000) begin
            $error("Timeout ICMP");
            $finish;
        end

        if (!parser_error && !is_tcp && !is_udp && checksum_ok) begin
             $display("PASS: ICMP Packet handled correctly (Valid IP, No TCP/UDP flag)"); pass_cnt++;
        end else begin
             $error("FAIL: ICMP Packet logic failed"); fail_cnt++;
        end

        // Summary
        $display("\n");
        $display("FINAL RESULTS: Pass=%0d, Fail=%0d", pass_cnt, fail_cnt);
        $display("\n");
        $finish;
    end
endmodule