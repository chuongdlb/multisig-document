pragma solidity ^0.4.23;

library HashUtils {

  function toSha256(string x)
    internal
    pure
    returns (bytes32)
  {
    return sha256(abi.encodePacked(x));
  }

  function toKeccak256(string x)
    internal
    pure
    returns (bytes32)
  {
    return keccak256(abi.encodePacked(x));
  }
}
