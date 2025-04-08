import {
    Finding,
    HandleTransaction,
    TransactionEvent,
    FindingSeverity,
    FindingType,
    getEthersProvider,
  } from "forta-agent";
  import { ethers } from "ethers";
  
  const MAX_UINT =
    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  
  // Handle the ERC20 Approval event
  const ERC20_APPROVAL_TOPIC = ethers.utils.id("Approval(address,address,uint256)");
  
  // Utility to check if address is a contract
  async function isContract(address: string): Promise<boolean> {
    const code = await getEthersProvider().getCode(address);
    return code !== "0x";
  }
  
  // Main detection logic
  export const handleTransaction: HandleTransaction = async (
    txEvent: TransactionEvent
  ) => {
    const findings: Finding[] = [];
  
    // Filter for Approval events
    const approvalEvents = txEvent.filterLog(ERC20_APPROVAL_TOPIC);
  
    for (const event of approvalEvents) {
      const [owner, spender, valueRaw] = event.args!;
      const value = valueRaw.toString();
  
      let reasons: string[] = [];
  
      // 1. MAX UINT (unlimited approval)
      if (value === MAX_UINT) {
        reasons.push("Unlimited approval amount (MAX_UINT)");
      }
  
      // 2. Approval to EOA
      const spenderIsContract = await isContract(spender);
      if (!spenderIsContract) {
        reasons.push("Approval to an externally owned account (EOA)");
      }
  
      // 3. New spender contract (low block age or no prior txs)
      const blockNumber = txEvent.blockNumber;
      const provider = getEthersProvider();
      const spenderHistory = await provider.getTransactionCount(spender);
      if (spenderIsContract && spenderHistory === 0) {
        reasons.push("Approval to newly deployed contract (no tx history)");
      }
  
      // 4. No previous interactions
      const from = txEvent.from.toLowerCase();
      const spenderLower = spender.toLowerCase();
      const hasInteractedBefore = txEvent.address.toLowerCase() === spenderLower;
      if (!hasInteractedBefore) {
        reasons.push("No prior interaction with spender");
      }
  
      // If any reasons found, report
      if (reasons.length > 0) {
        findings.push(
          Finding.fromObject({
            name: "Suspicious Token Approval",
            description: `Suspicious approval from ${owner} to ${spender}. Reason(s): ${reasons.join(
              "; "
            )}`,
            alertId: "VENN-APPROVAL-1",
            protocol: "ethereum",
            type: FindingType.Suspicious,
            severity: FindingSeverity.High,
            metadata: {
              owner,
              spender,
              value,
              reasons: reasons.join(", "),
              token: event.address,
              txHash: txEvent.hash,
            },
          })
        );
      }
    }
  
    return findings;
  };
  