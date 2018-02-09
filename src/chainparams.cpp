// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chrono>
#include <thread>

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "NY Times 07/Feb/2018 In Sweeping War on Obesity, Chile Slays Tony the Tiger";
    const CScript genesisOutputScript = CScript() << ParseHex("04242c4b5bf04bea0cdb77a8662f8615fcb072546c3803943198fb9932a60f3e775ebd2323fba6416aaa88229878d0e295e7589a7add8ab15d36c3064e61bd87ab") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 358914;
        consensus.BIP34Height = 710000;
        consensus.BIP34Hash = uint256S("fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf");
        consensus.BIP65Height = 918684; // bab3041e8977e0dc3eeff63fe707b92bde1dd449d8efafb248c27c8264cc311a
        consensus.BIP66Height = 811879; // 7aceee012833fa8952f8835d8b1b3ae233cd6ab08fdb27a771d2bd7bdc491894
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 67 * 68 * 69; // 1 hour 9 minutes
        consensus.nPowTargetSpacing = 68;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 4623; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1617356801; 

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1518019580; // February 7, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1617356801; 

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000ba50a60f8b56c7fe0");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x4c749bbf46afc748e7413c680fbcfbe6ce6cba1bb637e644e5c051231902d13e"); 

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf5;
        pchMessageStart[1] = 0xc4;
        pchMessageStart[2] = 0xb2;
        pchMessageStart[3] = 0xd1;
        nDefaultPort = 86700;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1518019580, 5186790, 0x1e0ffff0, 1, 67 * COIN);

        // printf("hash %s\n", consensus.hashGenesisBlock.ToString().c_str());
        // printf("gethash %s\n", genesis.GetHash().ToString().c_str());
        // printf("getpowhash %s\n", genesis.GetPoWHash().ToString().c_str());
        // printf("powlimit %s\n", consensus.powLimit.ToString().c_str());
        // printf("merkle %s\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("boolean %s\n", (genesis.GetPoWHash().ToString() > consensus.powLimit.ToString()) ? "True" : "False");

        // consensus.hashGenesisBlock = uint256S("0x0000069788d5ac8a51a7dfb9bd9bfc359a7f5823f218313132ac40b2e533cbbf");
        // if (true && genesis.GetPoWHash() != consensus.hashGenesisBlock) {
        //     printf("recalculating params for mainnet.\n");
        //     printf("old mainnet genesis nonce: %d\n", genesis.nNonce);
        //     printf("old mainnet genesis hash:  %s\n", consensus.hashGenesisBlock.ToString().c_str());
        //     // deliberately empty for loop finds nonce value.
        //     for(genesis.nNonce = 3682845; genesis.GetPoWHash().ToString() > consensus.powLimit.ToString(); genesis.nNonce++){ } 
        //     printf("new mainnet genesis merkle root: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //     printf("new mainnet genesis nonce: %d\n", genesis.nNonce);
        //     printf("new mainnet genesis hash: %s\n", genesis.GetPoWHash().ToString().c_str());
        // } 


        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x4c749bbf46afc748e7413c680fbcfbe6ce6cba1bb637e644e5c051231902d13e"));
        assert(genesis.hashMerkleRoot == uint256S("0x264654aa6624d6c0b0fa41da2815ce767dc40b37b3f93d5c8b1c8e11a1a12346"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("35.169.92.54", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,71);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,6);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,59);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,194);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x14, 0x88, 0xB3, 0x5E};
        base58Prefixes[EXT_SECRET_KEY] = {0x14, 0x88, 0xCD, 0xE1};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
                {  0, uint256S("0x4c749bbf46afc748e7413c680fbcfbe6ce6cba1bb637e644e5c051231902d13e")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block db42d00d824950a125f9b08b6b6c282c484781562fa8b3bd29d6ce4a2627c348 (height 1259851).
            1518019580, // * UNIX timestamp of last known number of transactions
            0,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            1     // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 358914;
        consensus.BIP34Height = 76;
        consensus.BIP34Hash = uint256S("8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573");
        consensus.BIP65Height = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.BIP66Height = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 67 * 68 * 69; // 1 hour 9 minutes
        consensus.nPowTargetSpacing = 68;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 4623; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1617356801; 

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1518019580; // February 7, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1617356801; 

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000364b0cbc3568");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x48ba01d037643d208a59dcee8331158fa982c2564453088b2ab9c75cb1dcd37d"); 

        pchMessageStart[0] = 0xf3;
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0xb8;
        pchMessageStart[3] = 0xe1;
        nDefaultPort = 19335;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(1518019580, 7789003, 0x1e0ffff0, 1, 67 * COIN);


        // printf("testnet hash %s\n", consensus.hashGenesisBlock.ToString().c_str());
        // printf("gethash %s\n", genesis.GetHash().ToString().c_str());
        // printf("getpowhash %s\n", genesis.GetPoWHash().ToString().c_str());
        // printf("powlimit %s\n", consensus.powLimit.ToString().c_str());
        // printf("merkle %s\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("boolean %s\n", (genesis.GetPoWHash().ToString() > consensus.powLimit.ToString()) ? "True" : "False");

        // consensus.hashGenesisBlock = uint256S("0x0000000b3cd2ccb962d89925245aca7a8709c56a3f5a3b502be02c0ae433bc83");
        // printf("here00");
        // if (true && genesis.GetPoWHash() != consensus.hashGenesisBlock) {
        //     printf("recalculating params for testnet.\n");
        //     printf("old testnet genesis nonce: %d\n", genesis.nNonce);
        //     printf("old testnet genesis hash:  %s\n", consensus.hashGenesisBlock.ToString().c_str());
        //     // deliberately empty for loop finds nonce value.
        //     for(genesis.nNonce = 6756722; genesis.GetPoWHash().ToString() > consensus.powLimit.ToString(); genesis.nNonce++){ } 
        //     printf("new testnet genesis merkle root: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //     printf("new testnet genesis nonce: %d\n", genesis.nNonce);
        //     printf("new testnet genesis hash: %s\n", genesis.GetPoWHash().ToString().c_str());
        // } 

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x48ba01d037643d208a59dcee8331158fa982c2564453088b2ab9c75cb1dcd37d"));
        assert(genesis.hashMerkleRoot == uint256S("0x264654aa6624d6c0b0fa41da2815ce767dc40b37b3f93d5c8b1c8e11a1a12346"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("35.169.92.54", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,131);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,198);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,68);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,217);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x86, 0xCB};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x84, 0x95};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));


        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
                {  0, uint256S("0x48ba01d037643d208a59dcee8331158fa982c2564453088b2ab9c75cb1dcd37d")},
            }
        };

        chainTxData = ChainTxData{
            1518019580,
            0,
            1
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 358914;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 67 * 68 * 69; // 1 hour 9 minutes
        consensus.nPowTargetSpacing = 68;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 4623; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xb3;
        pchMessageStart[2] = 0xb2;
        pchMessageStart[3] = 0xd1;
        nDefaultPort = 19444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1518019580, 5186790, 0x1e0ffff0, 1, 67 * COIN);

        // printf("regtest hash %s\n", consensus.hashGenesisBlock.ToString().c_str());
        // printf("gethash %s\n", genesis.GetHash().ToString().c_str());
        // printf("powlimit %s\n", consensus.powLimit.ToString().c_str());
        // printf("merkle %s\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("boolean %s\n", (genesis.GetHash().ToString() > consensus.powLimit.ToString()) ? "True" : "False");


        // consensus.hashGenesisBlock = uint256S("0x0000069788d5ac8a51a7dfb9bd9bfc359a7f5823f218313132ac40b2e533cbbf");
        // if (true && genesis.GetHash() != consensus.hashGenesisBlock) {
        //     printf("recalculating params for regtest.\n");
        //     printf("old regtest genesis nonce: %d\n", genesis.nNonce);
        //     printf("old regtest genesis hash:  %s\n", consensus.hashGenesisBlock.ToString().c_str());
        //     // deliberately empty for loop finds nonce value.
        //     for(genesis.nNonce = 3556722; genesis.GetHash().ToString() > consensus.powLimit.ToString(); genesis.nNonce++){ } 
        //     printf("new regtest genesis merkle root: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //     printf("new regtest genesis nonce: %d\n", genesis.nNonce);
        //     printf("new regtest genesis hash: %s\n", genesis.GetHash().ToString().c_str());
        // }

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x4c749bbf46afc748e7413c680fbcfbe6ce6cba1bb637e644e5c051231902d13e"));
        assert(genesis.hashMerkleRoot == uint256S("0x264654aa6624d6c0b0fa41da2815ce767dc40b37b3f93d5c8b1c8e11a1a12346"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = (CCheckpointData) {
            {
                {  0, uint256S("0x4c749bbf46afc748e7413c680fbcfbe6ce6cba1bb637e644e5c051231902d13e")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,141);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,199);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,78);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,209);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x86, 0xCB};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x84, 0x95};
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
