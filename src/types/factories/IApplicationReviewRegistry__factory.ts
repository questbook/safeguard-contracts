/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Signer, utils } from "ethers";
import { Provider } from "@ethersproject/providers";
import type {
  IApplicationReviewRegistry,
  IApplicationReviewRegistryInterface,
} from "../IApplicationReviewRegistry";

const _abi = [
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
      {
        internalType: "uint96",
        name: "",
        type: "uint96",
      },
    ],
    name: "reviews",
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
        internalType: "string",
        name: "",
        type: "string",
      },
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
];

export class IApplicationReviewRegistry__factory {
  static readonly abi = _abi;
  static createInterface(): IApplicationReviewRegistryInterface {
    return new utils.Interface(_abi) as IApplicationReviewRegistryInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): IApplicationReviewRegistry {
    return new Contract(
      address,
      _abi,
      signerOrProvider
    ) as IApplicationReviewRegistry;
  }
}