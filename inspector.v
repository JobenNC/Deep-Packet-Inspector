/*
Deep Packet Inspector
All packets will be preceeded by the bit stream:
h'A5A5A5A5
Count sessions for relevant protocols
*/

module inspector(
input rst_n, clk, data,
output reg[31:0] total_cnt,
output reg[7:0] skype_cnt,
output reg[7:0] ftp_cnt,
output reg[7:0] https_cnt,
output reg[7:0] telnet_cnt,
output reg[7:0] ssh_cnt,
output reg[7:0] snmp_cnt,
output reg[7:0] smtp_cnt,
output reg[7:0] nntp_cnt,
output reg[7:0] telnet_session,
output reg[7:0] skype_session,
output reg[7:0] ssh_session
);

reg[287:0] Dout;

reg[1:0] cState;
reg[1:0] nState;

reg[7:0] lastTelSess;
reg[7:0] lastSkypeSess;
reg[7:0] lastSshSess;

reg isFirstSsh;
reg isFirstTel;
reg isFirstSkype;

reg[8:0] countDown;

//unreasonably large shift register
always @(posedge clk) begin
    if (rst_n) 
        begin
        Dout <= { Dout[286:0], data };
    end
end


always @(posedge clk)
begin
    if (!rst_n) 
      begin
        cState <= 2'b00;
      end
    else 
      begin
        cState <= nState;
      end
end

always @(*)
begin
case(cState)

2'b00:
begin

countDown = 0;

total_cnt = 0;
ftp_cnt = 0;
skype_cnt = 0;
ssh_cnt = 0;
smtp_cnt = 0;
skype_cnt = 0;
https_cnt = 0;
telnet_cnt = 0;
snmp_cnt = 0;
nntp_cnt = 0;

ssh_session = 0;
skype_session = 0;
telnet_session = 0;

lastTelSess = 0;
lastSkypeSess = 0;
lastSshSess = 0;

isFirstSsh = 1;
isFirstTel = 1;
isFirstSkype = 1;

nState <= 2'b01;
end

2'b01:
begin
  if (countDown > 0) countDown = countDown - 1;
  if ((Dout[287:256] == 32'hA5A5A5A5) && (countDown == 0)) begin

    countDown = 288;
    total_cnt = total_cnt + 1;
    if (Dout[191:176] == 23399)
    begin
      skype_cnt = skype_cnt + 1;
        if ((Dout[119:112] > lastSkypeSess) || ((lastSkypeSess == 0) && (isFirstSkype == 1)))
        begin
        lastSkypeSess = Dout[119:112];
        skype_session = skype_session + 1;
        isFirstSkype = 0;
        end
    end
    else if (Dout[191:176] == 20)
    begin
      ftp_cnt = ftp_cnt + 4'b0001;
    end
    else if (Dout[191:176] == 443)
    begin
      https_cnt = https_cnt + 4'b0001;
    end
    else if (Dout[191:176] == 22)
    begin
      ssh_cnt = ssh_cnt + 4'b0001;
        if ((Dout[119:112] > lastSshSess) || ((lastSshSess == 0) && (isFirstSsh == 1)))
        begin
        lastSshSess = Dout[119:112];
        ssh_session = ssh_session + 1;
        isFirstSsh = 0;
        end
    end
    else if (Dout[191:176] == 23)
    begin
      telnet_cnt = telnet_cnt + 4'b0001;
        if ((Dout[119:112] > lastTelSess) || ((lastTelSess == 0) && (isFirstTel == 1)))
        begin
        lastTelSess = Dout[119:112];
        telnet_session = telnet_session + 1;
        isFirstTel = 0;
        end
    end
    else if (Dout[191:176] == 25)
    begin
      smtp_cnt = smtp_cnt + 4'b0001;
    end
    else if (Dout[191:176] == 161)
    begin
      snmp_cnt = snmp_cnt + 4'b0001;
    end
    else if (Dout[191:176] == 563)
    begin
      nntp_cnt = nntp_cnt + 4'b0001;
    end

    else 
    begin
    $display("failed check");
    end
  end
end
endcase

end

endmodule
