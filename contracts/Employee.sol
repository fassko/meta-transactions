// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

contract Employee {
  struct EmployeeData {
    uint256 employeeId;
    string employeeName;
  }

  EmployeeData private currentEmployee;

  struct MetaTransaction {
    uint256 nonce;
    address from;
    bytes functionSignature;
  }

  string public constant ERC712_VERSION = '1';

  /// Address of the executor. For signed transactions it will be signer.
  address internal currentContextAddress;

  bytes32 internal domainSeperator;

  mapping(address => uint256) private nonces;

  bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
      keccak256(
          bytes('EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)')
      );

  bytes32 private constant META_TRANSACTION_TYPEHASH =
      keccak256(bytes('MetaTransaction(uint256 nonce,address from,bytes functionSignature)'));

  constructor(string memory _domainSeperator) {
    _setDomainSeperator(_domainSeperator);
  }

  /**
   * @notice Meta transaction executed
   * @param _address Address of the signer
   * @param signer Executor address
   * @param functionSignature Function signature
   */
  event MetaTransactionExecuted(
      address _address,
      address payable signer,
      bytes functionSignature
  );

  /**
   * @notice Set domain seperator
   * @param name Domain seperator name
   */
  function _setDomainSeperator(string memory name) internal {
        domainSeperator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(ERC712_VERSION)),
                address(this),
                bytes32(getChainId())
            )
        );
    }

    /**
     * @notice Get domain seperator
     * @return Domain seperator in bytes
     */
    function getDomainSeperator() public view returns (bytes32) {
        return domainSeperator;
    }

  /**
   * @notice Get nonce for an address
   * @param _address Address
   * @return nonce Current address nonce
   */
  function getNonce(address _address) external view returns (uint256 nonce) {
      nonce = nonces[_address];
  }

  /**
   * @notice Execute meta transaction
   * @param _address Address of the signer
   * @param functionSignature Function signature
   * @param sigR `r` value of the signature
   * @param sigS `s` value of the signature
   * @param sigV `v` value of the signature
   * @return Returns data from function signature execution
   */
  function executeMetaTransaction(
      address _address,
      bytes memory functionSignature,
      bytes32 sigR,
      bytes32 sigS,
      uint8 sigV
  ) external returns (bytes memory) {
      MetaTransaction memory metaTx = MetaTransaction({
          nonce: nonces[_address],
          from: _address,
          functionSignature: functionSignature
      });

      require(verify(_address, metaTx, sigR, sigS, sigV), 'Signer and signature do not match');

      // increase nonce for user (to avoid re-use)
      nonces[_address] = nonces[_address] + 1;

      (bool success, bytes memory returnData) = address(this).call(
          abi.encodePacked(functionSignature, _address)
      );
      require(
          success,
          string(abi.encodePacked('Meta transaction execution failed ', returnData))
      );

      emit MetaTransactionExecuted(_address, payable(msg.sender), functionSignature);

      return returnData;
  }

  /**
   * @notice Get current chain identificator
   * @return Chain identificator
   */
  function getChainId() private view returns (uint256) {
      uint256 id;
      assembly {
          id := chainid()
      }
      return id;
  }

  /**
   * @notice Verify if signer is the same in the signed transaction
   * @param signer Signer address
   * @param metaTx Signed transaction
   * @param sigR R value of the signature
   * @param sigS S value of the signature
   * @param sigV V value of the signature
   */
  function verify(
      address signer,
      MetaTransaction memory metaTx,
      bytes32 sigR,
      bytes32 sigS,
      uint8 sigV
  ) private view returns (bool) {
      require(signer != address(0), 'Signer cant be zero address');

      return
          signer == ecrecover(toTypedMessageHash(hashMetaTransaction(metaTx)), sigV, sigR, sigS);
  }

  function toTypedMessageHash(bytes32 messageHash) private view returns (bytes32) {
      return keccak256(abi.encodePacked('\x19\x01', getDomainSeperator(), messageHash));
  }

  /**
   * @notice Hash the meta transaction data to bytes
   * @param metaTx Meta transaction data
   * @return Hashed meta transaction into bytes
   */
  function hashMetaTransaction(MetaTransaction memory metaTx) private pure returns (bytes32) {
      return
          keccak256(
              abi.encode(
                  META_TRANSACTION_TYPEHASH,
                  metaTx.nonce,
                  metaTx.from,
                  keccak256(metaTx.functionSignature)
              )
          );
  }

  /**
   * @notice Get the sender either from signed or regular transaction
   * @return sender Address of the sender
   */
  function msgSender() internal view returns (address sender) {
      if (msg.sender == address(this)) {
          bytes memory array = msg.data;
          uint256 index = msg.data.length;
          assembly {
              // Load the 32 bytes word from memory with the address on the lower 20 bytes, and mask those.
              sender := and(mload(add(array, index)), 0xffffffffffffffffffffffffffffffffffffffff)
          }
      } else {
          sender = msg.sender;
      }
      return sender;
  }

  
  /**
   * @notice Set current employee
   * @param id Employee identificator
   * @param name Employee name
   */
  function set(uint256 id, string memory name) external {
    currentEmployee = EmployeeData(id, name);
  }

  /**
   * @notice Get current employee
   * @return Current employee data object
   */
  function getCurrentEmployee() view external returns(EmployeeData memory) {
    return currentEmployee;
  }
}