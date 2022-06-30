-----------------------------------------------------------------------------
-- |
-- Module      :  Data.HarvestPE
-- Copyright   :  (c) Logan Leland, 2022
-- License     :  MIT (see the file LICENSE)
--
-- Maintainer  :  Logan Leland <ethicalmath@gmail.com>
-- Stability   :  experimental
-- Portability :  portable
--
-- Harvest (parse) PE Section Headers and Data.
--
-----------------------------------------------------------------------------

module Data.HarvestSection
  (
    Section,
    harvest
  )
  where

import Data.Word
import qualified Data.Binary.Get as G
import qualified Data.ByteString.Lazy as BSL 
import Control.Monad (replicateM)

data SectionHeader = SectionHeader
  { name :: BSL.ByteString
  , virtualSize :: Word32
  , virtualAddr :: Word32
  , sizeOfRawData :: Word32
  , pointerToRawData :: Word32
  , pointerToRelocations :: Word32
  , pointerToLineNumbers :: Word32
  , numberOfRelocations :: Word16
  , numberOfLineNumbers :: Word16
  , sCharacteristics :: Word32
  }
  deriving Show

harvestSectionData :: BSL.ByteString -> SectionHeader -> Section
harvestSectionData a b = flip G.runGet a $ do
  G.skip sOff
  dat <- G.getLazyByteString sSize
  return Section { sHeader = b
                 , sData = dat
                 }
  where
    sOff = fromIntegral $ pointerToRawData b
    sSize = fromIntegral $ sizeOfRawData b

data Section = Section
  { sHeader :: SectionHeader
  , sData :: BSL.ByteString
  }
  deriving Show

harvest :: Int -> Int -> BSL.ByteString -> [Section]
harvest a b c = do
  let sHeaders = G.runGet (harvestSectionHeader a b) c
  map (harvestSectionData c) sHeaders

harvestSectionHeader :: Int -> Int -> G.Get [SectionHeader]
harvestSectionHeader a b = do
  G.skip a
  replicateM b $ harvestSectionHeader'

harvestSectionHeader' :: G.Get SectionHeader
harvestSectionHeader' = do
  name' <- G.getLazyByteString 8
  virtualSize' <- G.getWord32le
  virtualAddr' <- G.getWord32le
  sizeOfRawData' <- G.getWord32le
  pointerToRawData' <- G.getWord32le
  pointerToRelocations' <- G.getWord32le
  pointerToLineNumbers' <- G.getWord32le
  numberOfRelocations' <- G.getWord16le
  numberOfLineNumbers' <- G.getWord16le
  sCharacteristics' <- G.getWord32le
  return SectionHeader { name = BSL.filter (not . (==0)) name'
                       , virtualSize = virtualSize'
                       , virtualAddr = virtualAddr'
                       , sizeOfRawData = sizeOfRawData'
                       , pointerToRawData = pointerToRawData'
                       , pointerToRelocations = pointerToRelocations'
                       , pointerToLineNumbers = pointerToLineNumbers'
                       , numberOfRelocations = numberOfRelocations'
                       , numberOfLineNumbers = numberOfLineNumbers'
                       , sCharacteristics = sCharacteristics'
                       }
