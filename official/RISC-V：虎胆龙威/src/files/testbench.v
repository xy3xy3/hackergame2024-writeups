`timescale 1 ns / 1 ps
 //`define VERBOSE

module testbench;

	integer f;
	integer i;
	integer j;
	integer t;

	reg clk = 1;
	reg resetn = 0;
	wire trap;

	always #5 clk = ~clk;

	initial begin
		repeat (100) @(posedge clk);
		resetn <= 1;
	end

	wire        mem_axi_awvalid;
	reg         mem_axi_awready = 0;
	wire [31:0] mem_axi_awaddr;
	wire [ 2:0] mem_axi_awprot;

	wire        mem_axi_wvalid;
	reg         mem_axi_wready = 0;
	wire [31:0] mem_axi_wdata;
	wire [ 3:0] mem_axi_wstrb;

	reg  mem_axi_bvalid = 0;
	wire mem_axi_bready;

	wire        mem_axi_arvalid;
	reg         mem_axi_arready = 0;
	wire [31:0] mem_axi_araddr;
	wire [ 2:0] mem_axi_arprot;

	reg         mem_axi_rvalid = 0;
	wire        mem_axi_rready;
	reg  [31:0] mem_axi_rdata;

	picorv32_axi uut (
		.clk            (clk            ),
		.resetn         (resetn         ),
		.trap           (trap           ),
		.mem_axi_awvalid(mem_axi_awvalid),
		.mem_axi_awready(mem_axi_awready),
		.mem_axi_awaddr (mem_axi_awaddr ),
		.mem_axi_awprot (mem_axi_awprot ),
		.mem_axi_wvalid (mem_axi_wvalid ),
		.mem_axi_wready (mem_axi_wready ),
		.mem_axi_wdata  (mem_axi_wdata  ),
		.mem_axi_wstrb  (mem_axi_wstrb  ),
		.mem_axi_bvalid (mem_axi_bvalid ),
		.mem_axi_bready (mem_axi_bready ),
		.mem_axi_arvalid(mem_axi_arvalid),
		.mem_axi_arready(mem_axi_arready),
		.mem_axi_araddr (mem_axi_araddr ),
		.mem_axi_arprot (mem_axi_arprot ),
		.mem_axi_rvalid (mem_axi_rvalid ),
		.mem_axi_rready (mem_axi_rready ),
		.mem_axi_rdata  (mem_axi_rdata  )
	);

	reg [31:0] memory [0:1024-1]; // 4 KB memory
`ifdef FRAGILITY
	reg mem_frag [0:1024-1];
`endif

	always @(posedge clk) begin
		mem_axi_awready <= 0;
		mem_axi_wready <= 0;
		mem_axi_arready <= 0;

		if (!mem_axi_bvalid || mem_axi_bready) begin
			mem_axi_bvalid <= 0;
			if (mem_axi_awvalid && mem_axi_wvalid && !mem_axi_awready && !mem_axi_wready) begin
`ifdef VERBOSE
				$display("WR: ADDR=%08x DATA=%08x STRB=%04b", mem_axi_awaddr, mem_axi_wdata, mem_axi_wstrb);
`endif
				if (mem_axi_awaddr < 64*1024) begin
					if (mem_axi_wstrb[0]) memory[mem_axi_awaddr >> 2][ 7: 0] <= mem_axi_wdata[ 7: 0];
					if (mem_axi_wstrb[1]) memory[mem_axi_awaddr >> 2][15: 8] <= mem_axi_wdata[15: 8];
					`ifndef THREE_OF_THE_FOUR
						if (mem_axi_wstrb[2]) memory[mem_axi_awaddr >> 2][23:16] <= mem_axi_wdata[23:16];
					`endif
					if (mem_axi_wstrb[3]) memory[mem_axi_awaddr >> 2][31:24] <= mem_axi_wdata[31:24];
				end
				if (mem_axi_awaddr == 32'h1000_0000) begin
`ifdef VERBOSE
					if (32 <= mem_axi_wdata && mem_axi_wdata < 128)
						$display("OUT: '%c'", mem_axi_wdata);
					else
						$display("OUT: %3d", mem_axi_wdata);
`else
					$write("%c", mem_axi_wdata);
					$fflush();
`endif
				end
				mem_axi_awready <= 1;
				mem_axi_wready <= 1;
				mem_axi_bvalid <= 1;
			end
		end

		if (!mem_axi_rvalid || mem_axi_rready) begin
			mem_axi_rvalid <= 0;
			if (mem_axi_arvalid && !mem_axi_arready) begin
`ifdef VERBOSE
				$display("RD: ADDR=%08x DATA=%08x", mem_axi_araddr, memory[mem_axi_araddr >> 2]);
`endif
				mem_axi_arready <= 1;
				`ifdef THREE_OF_THE_FOUR
					mem_axi_rdata <= memory[mem_axi_araddr >> 2] & 32'hFF00FFFF;
				`else
					`ifdef FRAGILITY
						mem_axi_rdata <= mem_frag[mem_axi_araddr >> 2] ? 32'h0 : memory[mem_axi_araddr >> 2];
						mem_frag[mem_axi_araddr >> 2] <= 1;
					`else
						mem_axi_rdata <= memory[mem_axi_araddr >> 2];
					`endif
				`endif
				mem_axi_rvalid <= 1;
			end
		end
	end

	reg [31:0] numbers [0:16-1];
	reg [31:0] numbers_orig [0:16-1];
	initial begin
		//$dumpfile("testbench.vcd");
		//$dumpvars(0, testbench);
		`ifndef FAULT_IN_THE_HART
		`ifndef FRAGILITY
		`ifndef THREE_OF_THE_FOUR
			$display("This is not how we play... ");
			$fatal;
		`endif
		`endif
		`endif
		$display("Preparing memories... ");
		for (integer i=0; i<1024; i=i+1) begin
			memory[i] = 0;
			`ifdef FRAGILITY
				mem_frag[i] = 0;
			`endif
		end
		$readmemh("/tmp/firmware.hex", memory);

		f = $fopen("/tmp/numbers.hex", "r");
		for (i=0; i<16; i=i+1) begin
			j = $fscanf(f, "%h", numbers[i]);
			memory[1024 - 32 + i] = numbers[i];
			numbers_orig[i] = numbers[i];
		end
		$fclose(f);

		for (i=0; i<16-1; i=i+1) begin
			for (j=0; j<16-i-1; j=j+1) begin
				if (numbers[j] > numbers[j+1]) begin
					t = numbers[j+1];
					numbers[j+1] = numbers[j];
					numbers[j] = t;
				end
			end
		end

		$display("Starting processor... ");
		repeat (1000000) @(posedge clk);

		$display("Compare results: ");
		f = 0;
		for (i=0; i<16; i=i+1) begin
			if (memory[1024 - 16 + i] != numbers[i]) begin
				$display("Failed! Expected: %h, yours: %h, original: %h", numbers[i], memory[1024 - 16 + i], numbers_orig[i]);
				f = 1;
				//$finish;
			end else begin
				$display("%h", numbers[i]);
			end
		end
		if (f == 0) begin
			$display("Successful");
			$finish;
		end else begin
			$display("Failed");
			$fatal;
		end
	end

	`ifndef FRAGILITY
	always @(posedge clk) begin
		if (resetn && trap) begin
			repeat (10) @(posedge clk);
			$display("TRAP");
			$fatal;
		end
	end
	`endif
endmodule
