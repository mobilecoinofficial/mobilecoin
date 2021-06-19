//! Convert to/from blockchain::ArchiveBlock

use crate::{blockchain, convert::ConversionError};
use mc_transaction_core::compute_block_id;
use protobuf::RepeatedField;
use std::convert::TryFrom;

/// Convert mc_transaction_core::BlockData --> blockchain::ArchiveBlock.
impl From<&mc_transaction_core::BlockData> for blockchain::ArchiveBlock {
    fn from(src: &mc_transaction_core::BlockData) -> Self {
        let bc_block = blockchain::Block::from(src.block());
        let bc_block_contents = blockchain::BlockContents::from(src.contents());

        let mut archive_block_v1 = blockchain::ArchiveBlockV1::new();
        archive_block_v1.set_block(bc_block);
        archive_block_v1.set_block_contents(bc_block_contents);

        if let Some(signature) = src.signature() {
            let bc_signature = blockchain::BlockSignature::from(signature);
            archive_block_v1.set_signature(bc_signature);
        }

        let mut archive_block = blockchain::ArchiveBlock::new();
        archive_block.set_v1(archive_block_v1);

        archive_block
    }
}

/// Convert from blockchain::ArchiveBlock --> mc_transaction_core::BlockData
impl TryFrom<&blockchain::ArchiveBlock> for mc_transaction_core::BlockData {
    type Error = ConversionError;

    fn try_from(src: &blockchain::ArchiveBlock) -> Result<Self, Self::Error> {
        if !src.has_v1() {
            return Err(ConversionError::ObjectMissing);
        }

        let block = mc_transaction_core::Block::try_from(src.get_v1().get_block())?;

        let block_contents =
            mc_transaction_core::BlockContents::try_from(src.get_v1().get_block_contents())?;

        let signature = src
            .get_v1()
            .signature
            .as_ref()
            .map(mc_transaction_core::BlockSignature::try_from)
            .transpose()?;

        if let Some(signature) = signature.as_ref() {
            signature
                .verify(&block)
                .map_err(|_| ConversionError::InvalidSignature)?;
        }

        if block.contents_hash != block_contents.hash() {
            return Err(ConversionError::InvalidContents);
        }

        Ok(mc_transaction_core::BlockData::new(
            block,
            block_contents,
            signature,
        ))
    }
}

/// Convert &[mc_transaction_core::BlockData] -> blockchain::ArchiveBlocks
impl From<&[mc_transaction_core::BlockData]> for blockchain::ArchiveBlocks {
    fn from(src: &[mc_transaction_core::BlockData]) -> Self {
        let mut archive_blocks = blockchain::ArchiveBlocks::new();
        archive_blocks.set_blocks(RepeatedField::from_vec(
            src.iter().map(blockchain::ArchiveBlock::from).collect(),
        ));

        archive_blocks
    }
}

/// Convert blockchain::ArchiveBlocks -> Vec<mc_transaction_core::BlockData>
impl TryFrom<&blockchain::ArchiveBlocks> for Vec<mc_transaction_core::BlockData> {
    type Error = ConversionError;

    fn try_from(src: &blockchain::ArchiveBlocks) -> Result<Self, Self::Error> {
        let blocks_data = src
            .get_blocks()
            .iter()
            .map(mc_transaction_core::BlockData::try_from)
            .collect::<Result<Vec<_>, ConversionError>>()?;

        if blocks_data.len() > 1 {
            // Ensure blocks_data form a legitimate chain of blocks.
            for i in 1..blocks_data.len() {
                let parent_block = &blocks_data[i - 1].block();
                let block = &blocks_data[i].block();

                let expected_block_id = compute_block_id(
                    block.version,
                    &parent_block.id,
                    block.index,
                    block.cumulative_txo_count,
                    &block.root_element,
                    &block.contents_hash,
                );
                if expected_block_id != block.id {
                    return Err(ConversionError::InvalidContents);
                }
            }
        }

        Ok(blocks_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_crypto_keys::{Ed25519Private, RistrettoPublic};
    use mc_transaction_core::{
        encrypted_fog_hint::ENCRYPTED_FOG_HINT_LEN,
        membership_proofs::Range,
        ring_signature::KeyImage,
        tx::{TxOut, TxOutMembershipElement, TxOutMembershipHash},
        Amount, Block, BlockContents, BlockData, BlockID, BlockSignature,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    fn generate_test_blocks_data(num_blocks: u64) -> Vec<BlockData> {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut blocks_data = Vec::new();
        let mut last_block: Option<Block> = None;

        for block_idx in 0..num_blocks {
            let tx_out = TxOut {
                amount: Amount::new(1u64 << 13, &RistrettoPublic::from_random(&mut rng)).unwrap(),
                target_key: RistrettoPublic::from_random(&mut rng).into(),
                public_key: RistrettoPublic::from_random(&mut rng).into(),
                e_fog_hint: (&[0u8; ENCRYPTED_FOG_HINT_LEN]).into(),
                e_memo: vec![0u8; 34],
            };
            let key_image = KeyImage::from(block_idx);

            let parent_block_id = last_block
                .map(|block| block.id.clone())
                .unwrap_or_else(|| BlockID::try_from(&[1u8; 32][..]).unwrap());

            let block_contents = BlockContents::new(vec![key_image.clone()], vec![tx_out.clone()]);
            let block = Block::new(
                1,
                &parent_block_id,
                99 + block_idx,
                400 + block_idx,
                &TxOutMembershipElement {
                    range: Range::new(10, 20).unwrap(),
                    hash: TxOutMembershipHash::from([12u8; 32]),
                },
                &block_contents,
            );

            last_block = Some(block.clone());

            let signer = Ed25519Private::from_random(&mut rng);
            let signature =
                BlockSignature::from_block_and_keypair(&block, &(signer.into())).unwrap();

            let block_data = BlockData::new(block, block_contents, Some(signature));
            blocks_data.push(block_data);
        }

        blocks_data
    }

    #[test]
    // mc_transaction_core::BlockData <--> blockchain::ArchiveBlock
    fn test_archive_block() {
        let block_data = generate_test_blocks_data(1).pop().unwrap();

        // mc_transaction_core::BlockData -> blockchain::ArchiveBlock
        let archive_block = blockchain::ArchiveBlock::from(&block_data);
        assert_eq!(
            block_data.block(),
            &Block::try_from(archive_block.get_v1().get_block()).unwrap(),
        );
        assert_eq!(
            block_data.contents(),
            &BlockContents::try_from(archive_block.get_v1().get_block_contents()).unwrap()
        );
        assert_eq!(
            block_data.signature().clone().unwrap(),
            BlockSignature::try_from(archive_block.get_v1().get_signature()).unwrap()
        );

        // blockchain::ArchiveBlock -> mc_transaction_core::BlockData
        let block_data2 = BlockData::try_from(&archive_block).unwrap();
        assert_eq!(block_data, block_data2);
    }

    #[test]
    // Attempting to convert an ArchiveBlock with invalid signature or contents
    // should fail.
    fn try_from_blockchain_archive_block_rejects_invalid() {
        let block_data = generate_test_blocks_data(1).pop().unwrap();

        // ArchiveBlock with invalid signature cannot be converted back to BlockData
        let mut archive_block = blockchain::ArchiveBlock::from(&block_data);
        archive_block
            .mut_v1()
            .mut_signature()
            .mut_signature()
            .mut_data()[0] += 1;
        assert_eq!(
            BlockData::try_from(&archive_block),
            Err(ConversionError::InvalidSignature)
        );

        // ArchiveBlock with invalid contents cannot be converted back to BlockData
        let mut archive_block = blockchain::ArchiveBlock::from(&block_data);
        archive_block
            .mut_v1()
            .mut_block_contents()
            .mut_key_images()
            .clear();
        assert_eq!(
            BlockData::try_from(&archive_block),
            Err(ConversionError::InvalidContents)
        );
    }

    #[test]
    // Vec<mc_transaction_core::BlockData> <--> blockchain::ArchiveBlocks
    fn test_archive_blocks() {
        let blocks_data = generate_test_blocks_data(10);

        // Vec<mc_transaction_core::BlockData> -> blockchain::ArchiveBlocks
        let archive_blocks = blockchain::ArchiveBlocks::from(&blocks_data[..]);
        for (i, block_data) in blocks_data.iter().enumerate() {
            let archive_block = &archive_blocks.get_blocks()[i];
            assert_eq!(
                block_data.block(),
                &Block::try_from(archive_block.get_v1().get_block()).unwrap(),
            );
            assert_eq!(
                block_data.contents(),
                &BlockContents::try_from(archive_block.get_v1().get_block_contents()).unwrap()
            );
            assert_eq!(
                block_data.signature().clone().unwrap(),
                BlockSignature::try_from(archive_block.get_v1().get_signature()).unwrap()
            );
        }

        // blockchain::ArchiveBlocks -> Vec<mc_transaction_core::BlockData>
        let blocks_data2 = Vec::<BlockData>::try_from(&archive_blocks).unwrap();
        assert_eq!(blocks_data, blocks_data2);
    }

    #[test]
    // blockchain::ArchiveBlocks -> Vec<mc_transaction_core::BlockData> should fail
    // if the blocks to not form a chain.
    fn test_try_from_blockchain_archive_blocks_rejects_invalid() {
        let blocks_data = generate_test_blocks_data(10);
        let mut archive_blocks = blockchain::ArchiveBlocks::from(&blocks_data[..]);
        archive_blocks.mut_blocks().remove(5);

        assert_eq!(
            Vec::<BlockData>::try_from(&archive_blocks),
            Err(ConversionError::InvalidContents),
        );
    }
}
