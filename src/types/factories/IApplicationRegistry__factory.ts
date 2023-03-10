/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Signer, utils } from "ethers";
import { Provider } from "@ethersproject/providers";
import type {
  IApplicationRegistry,
  IApplicationRegistryInterface,
} from "../IApplicationRegistry";

const _abi = [
  {
    inputs: [
      {
        internalType: "uint96",
        name: "",
        type: "uint96",
      },
    ],
    name: "applications",
    outputs: [
      {
        internalType: "uint96",
        name: "",
        type: "uint96",
      },
      {
        internalType: "uint96",
        name: "",
        type: "uint96",
      },
      {
        internalType: "address",
        name: "",
        type: "address",
      },
      {
        internalType: "address",
        name: "",
        type: "address",
      },
      {
        internalType: "uint48",
        name: "",
        type: "uint48",
      },
      {
        internalType: "uint48",
        name: "",
        type: "uint48",
      },
      {
        internalType: "string",
        name: "",
        type: "string",
      },
      {
        internalType: "uint96",
        name: "",
        type: "uint96",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "eoaToScw",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
];

export class IApplicationRegistry__factory {
  static readonly abi = _abi;
  static createInterface(): IApplicationRegistryInterface {
    return new utils.Interface(_abi) as IApplicationRegistryInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): IApplicationRegistry {
    return new Contract(
      address,
      _abi,
      signerOrProvider
    ) as IApplicationRegistry;
  }
}
