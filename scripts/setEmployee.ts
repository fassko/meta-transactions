import { ethers, network } from "hardhat";

async function main() {
  
  // deploy the smart contract
  const Employee = await ethers.getContractFactory("Employee");
  const employee = await Employee.deploy('Employee');
  await employee.deployed();

  console.log("Emplyee smart contract deployed to ", employee.address);

  // Get signer and executor wallets
  const [signer, executor] = await ethers.getSigners();

  // Create the function signature
  const transaction = await employee.populateTransaction.set(1, 'John');

  console.log(transaction);

  // Define transaction types
  const types = {
    "MetaTransaction": [
      {
        "name": "nonce",
        "type": "uint256"
      },
      {
        "name": "from",
        "type": "address"
      },
      {
        "name": "functionSignature",
        "type": "bytes"
      }
    ]
  };

  // Salt is chain identifier
  const salt = ethers.utils.hexZeroPad(ethers.utils.hexValue(network.config.chainId ?? 0), 32);

  // Domain so we can verify the signed transaction
  const domain = {
    name: "Employee",
    version: "1",
    verifyingContract: transaction.to,
    salt: salt
  };

  // Get the nonce for the user
  const nonce = await employee.getNonce(signer.address);

  // Construct the transaction message
  const message = {
    "nonce": nonce,
    "from": signer.address,
    "functionSignature": transaction.data ?? ''
  };

  // Sign the transaction
  const signature = await signer._signTypedData(domain, types, message);
  console.log("Signature ", signature);

  const signerAddress = ethers.utils.verifyTypedData(
    domain,
    types,
    message,
    signature
  );
  console.log("Signer address in the signature is ", signerAddress);
  console.log("Signer address is ", signer.address);

  // Get signature parts - r, s, v values
  const { r, s, v } = ethers.utils.splitSignature(signature);

  // Execute the signed transaction with another account who will pay for the gas
  await employee.connect(executor).executeMetaTransaction(
    signer.address,
    transaction.data ?? '', // function signature
    r,
    s,
    v
  );

  // Verify if the current employee has been chnanged
  const currentEmployee = await employee.getCurrentEmployee();
  console.log(">>>>", currentEmployee);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
