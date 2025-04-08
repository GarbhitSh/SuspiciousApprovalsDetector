import {
    FindingType,
    FindingSeverity,
    createTransactionEvent,
    HandleTransaction,
    getEthersProvider,
  } from "forta-agent";
  import { ethers } from "ethers";
  import { handleTransaction } from "../detectors/SuspiciousApprovalsDetector";
  
  // Mock provider
  jest.mock("forta-agent", () => {
    const originalModule = jest.requireActual("forta-agent");
    return {
      ...originalModule,
      getEthersProvider: jest.fn(),
    };
  });
  
  const mockGetCode = jest.fn();
  const mockGetTransactionCount = jest.fn();
  (getEthersProvider as jest.Mock).mockReturnValue({
    getCode: mockGetCode,
    getTransactionCount: mockGetTransactionCount,
  });
  
  describe("SuspiciousApprovalsDetector", () => {
    const approvalEventSignature = "Approval(address,address,uint256)";
    const approvalTopic = ethers.utils.id(approvalEventSignature);
  
    const createMockApprovalLog = ({
      owner,
      spender,
      value,
      token,
    }: {
      owner: string;
      spender: string;
      value: string;
      token: string;
    }) => ({
      address: token,
      topics: [
        approvalTopic,
        ethers.utils.hexZeroPad(owner, 32),
        ethers.utils.hexZeroPad(spender, 32),
      ],
      args: [owner, spender, ethers.BigNumber.from(value)],
    });
  
    it("should NOT trigger for safe approval", async () => {
      mockGetCode.mockResolvedValue("0x6001"); // is contract
      mockGetTransactionCount.mockResolvedValue(10); // has history
  
      const mockLog = createMockApprovalLog({
        owner: "0xabc0000000000000000000000000000000000000",
        spender: "0xdef0000000000000000000000000000000000000",
        value: "1000000000000000000", // not MAX_UINT
        token: "0xtoken000000000000000000000000000000000000",
      });
  
      const txEvent = createTransactionEvent({
        transaction: {
          from: mockLog.args[0],
          to: mockLog.args[1],
          data: "0x",
        },
        logs: [mockLog],
        blockNumber: 12345678,
      });
  
      const findings = await handleTransaction(txEvent);
      expect(findings).toStrictEqual([]);
    });
  
    it("should trigger for MAX_UINT approval", async () => {
      mockGetCode.mockResolvedValue("0x6001");
      mockGetTransactionCount.mockResolvedValue(5);
  
      const MAX_UINT =
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  
      const mockLog = createMockApprovalLog({
        owner: "0xabc0000000000000000000000000000000000000",
        spender: "0xdef0000000000000000000000000000000000000",
        value: MAX_UINT,
        token: "0xtoken000000000000000000000000000000000000",
      });
  
      const txEvent = createTransactionEvent({
        transaction: {
          from: mockLog.args[0],
          to: mockLog.args[1],
          data: "0x",
        },
        logs: [mockLog],
        blockNumber: 12345678,
      });
  
      const findings = await handleTransaction(txEvent);
      expect(findings.length).toBe(1);
      expect(findings[0].name).toBe("Suspicious Token Approval");
      expect(findings[0].metadata.reasons).toContain("Unlimited approval");
    });
  
    it("should trigger for approval to EOA", async () => {
      mockGetCode.mockResolvedValue("0x"); // EOA
      mockGetTransactionCount.mockResolvedValue(1);
  
      const mockLog = createMockApprovalLog({
        owner: "0xabc0000000000000000000000000000000000000",
        spender: "0xdef0000000000000000000000000000000000000",
        value: "100000",
        token: "0xtoken000000000000000000000000000000000000",
      });
  
      const txEvent = createTransactionEvent({
        transaction: {
          from: mockLog.args[0],
          to: mockLog.args[1],
          data: "0x",
        },
        logs: [mockLog],
        blockNumber: 12345678,
      });
  
      const findings = await handleTransaction(txEvent);
      expect(findings.length).toBe(1);
      expect(findings[0].metadata.reasons).toContain("externally owned account");
    });
  
    it("should trigger for newly deployed contract approval", async () => {
      mockGetCode.mockResolvedValue("0x6001");
      mockGetTransactionCount.mockResolvedValue(0); // no tx history
  
      const mockLog = createMockApprovalLog({
        owner: "0xabc0000000000000000000000000000000000000",
        spender: "0xnew00000000000000000000000000000000000000",
        value: "100000",
        token: "0xtoken000000000000000000000000000000000000",
      });
  
      const txEvent = createTransactionEvent({
        transaction: {
          from: mockLog.args[0],
          to: mockLog.args[1],
          data: "0x",
        },
        logs: [mockLog],
        blockNumber: 12345678,
      });
  
      const findings = await handleTransaction(txEvent);
      expect(findings.length).toBe(1);
      expect(findings[0].metadata.reasons).toContain("newly deployed contract");
    });
  });
  