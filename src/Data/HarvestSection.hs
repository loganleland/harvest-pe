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
import Data.Bits (Bits, testBit)
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

data ShFlag = IMAGE_SCN_TYPE_NO_PAD | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE |
             IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA |
             IMAGE_SCN_LNK_OTHER | IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE |
             IMAGE_SCN_LNK_COMDAT | IMAGE_SCN_GPREL | IMAGE_SCN_MEM_PURGEABLE |
             IMAGE_SCN_MEM_16BIT | IMAGE_SCN_MEM_LOCKED | IMAGE_SCN_MEM_PRELOAD |
             IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_ALIGN_2BYTES | IMAGE_SCN_ALIGN_4BYTES |
             IMAGE_SCN_ALIGN_8BYTES | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_ALIGN_32BYTES |
             IMAGE_SCN_ALIGN_64BYTES | IMAGE_SCN_ALIGN_128BYTES | IMAGE_SCN_ALIGN_256BYTES |
             IMAGE_SCN_ALIGN_512BYTES | IMAGE_SCN_ALIGN_1024BYTES | IMAGE_SCN_ALIGN_2048BYTES |
             IMAGE_SCN_ALIGN_4096BYTES | IMAGE_SCN_ALIGN_8192BYTES | IMAGE_SCN_LNK_NRELOC_OVFL |
             IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_NOT_CACHED | IMAGE_SCN_MEM_NOT_PAGED |
             IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_SHARED
  deriving (Show, Eq)

getShFlag :: Word32 -> [ShFlag]
getShFlag = getShFlag' 32

getShFlag' :: Bits a => Int -> a -> [ShFlag]
getShFlag' 4 a = if testBit a 4 then IMAGE_SCN_TYPE_NO_PAD : []
                 else []

getShFlag' 6 a = if testBit a 6 then IMAGE_SCN_CNT_CODE : getShFlag' 4 a
                 else getShFlag' 4 a

getShFlag' 7 a = if testBit a 7 then IMAGE_SCN_CNT_INITIALIZED_DATA : getShFlag' 6 a
                 else getShFlag' 6 a

getShFlag' 8 a = if testBit a 8 then IMAGE_SCN_CNT_UNINITIALIZED_DATA : getShFlag' 7 a
                 else getShFlag' 7 a

getShFlag' 9 a = if testBit a 9 then IMAGE_SCN_LNK_OTHER : getShFlag' 8 a
                 else getShFlag' 8 a

getShFlag' 10 a = if testBit a 10 then IMAGE_SCN_LNK_INFO : getShFlag' 9 a
                  else getShFlag' 9 a

getShFlag' 12 a = if testBit a 12 then IMAGE_SCN_LNK_REMOVE : getShFlag' 10 a
                  else getShFlag' 10 a

getShFlag' 13 a = if testBit a 13 then IMAGE_SCN_LNK_COMDAT : getShFlag' 12 a
                  else getShFlag' 12 a

getShFlag' 16 a = if testBit a 16 then IMAGE_SCN_GPREL : getShFlag' 13 a
                  else getShFlag' 13 a

getShFlag' 18 a = if testBit a 18 then IMAGE_SCN_MEM_16BIT : IMAGE_SCN_MEM_PURGEABLE : getShFlag' 16 a
                  else getShFlag' 16 a

getShFlag' 19 a = if testBit a 19 then IMAGE_SCN_MEM_LOCKED : getShFlag' 18 a
                  else getShFlag' 18 a

getShFlag' 20 a = if testBit a 20 then IMAGE_SCN_MEM_PRELOAD : getShFlag' 19 a
                  else getShFlag' 19 a

getShFlag' 21 a = if testBit a 21 then IMAGE_SCN_ALIGN_1BYTES : getShFlag' 20 a
                  else getShFlag' 20 a

getShFlag' 22 a = if testBit a 22 && testBit a 21
                  then IMAGE_SCN_ALIGN_4BYTES : getShFlag' 20 a
                  else if testBit a 22
                  then IMAGE_SCN_ALIGN_2BYTES : getShFlag' 20 a
                  else getShFlag' 20 a

getShFlag' 23 a = if testBit a 23 && testBit a 22 && testBit a 21
                  then IMAGE_SCN_ALIGN_64BYTES : getShFlag' 20 a
                  else if testBit a 23 && testBit a 22
                  then IMAGE_SCN_ALIGN_32BYTES : getShFlag' 20 a
                  else if testBit a 23 && testBit a 21
                  then IMAGE_SCN_ALIGN_16BYTES : getShFlag' 20 a
                  else if testBit a 23
                  then IMAGE_SCN_ALIGN_8BYTES : getShFlag' 20 a
                  else getShFlag' 22 a

getShFlag' 24 a = if testBit a 24 && testBit a 23 && testBit a 22
                  then IMAGE_SCN_ALIGN_8192BYTES : getShFlag' 20 a
                  else if testBit a 24 && testBit a 23 && testBit a 21
                  then IMAGE_SCN_ALIGN_4096BYTES : getShFlag' 20 a
                  else if testBit a 24 && testBit a 23
                  then IMAGE_SCN_ALIGN_2048BYTES : getShFlag' 20 a
                  else if testBit a 24 && testBit a 22 && testBit a 21
                  then IMAGE_SCN_ALIGN_1024BYTES : getShFlag' 20 a
                  else if testBit a 24 && testBit a 22
                  then IMAGE_SCN_ALIGN_512BYTES : getShFlag' 20 a
                  else if testBit a 24 && testBit a 22
                  then IMAGE_SCN_ALIGN_256BYTES : getShFlag' 20 a
                  else if testBit a 24
                  then IMAGE_SCN_ALIGN_128BYTES : getShFlag' 20 a
                  else getShFlag' 23 a

getShFlag' 25 a = if testBit a 25 then IMAGE_SCN_LNK_NRELOC_OVFL : getShFlag' 24 a else getShFlag' 24 a 
getShFlag' 26 a = if testBit a 26 then IMAGE_SCN_MEM_DISCARDABLE : getShFlag' 25 a else getShFlag' 25 a 
getShFlag' 27 a = if testBit a 27 then IMAGE_SCN_MEM_NOT_CACHED : getShFlag' 26 a else getShFlag' 26 a 
getShFlag' 28 a = if testBit a 28 then IMAGE_SCN_MEM_NOT_PAGED : getShFlag' 27 a else getShFlag' 27 a 
getShFlag' 29 a = if testBit a 29 then IMAGE_SCN_MEM_SHARED : getShFlag' 28 a else getShFlag' 28 a 
getShFlag' 30 a = if testBit a 30 then IMAGE_SCN_MEM_EXECUTE : getShFlag' 29 a else getShFlag' 29 a 
getShFlag' 31 a = if testBit a 31 then IMAGE_SCN_MEM_READ : getShFlag' 30 a else getShFlag' 30 a 
getShFlag' 32 a = if testBit a 32 then IMAGE_SCN_MEM_WRITE : getShFlag' 31 a else getShFlag' 31 a 

harvestSectionData :: BSL.ByteString -> SectionHeader -> Section
harvestSectionData a b = flip G.runGet a $ do
  G.skip sOff
  dat <- G.getLazyByteString sSize
  return Section { sHeader = b
                 , sFlags = getShFlag (sCharacteristics b)
                 , sData = dat
                 }
  where
    sOff = fromIntegral $ pointerToRawData b
    sSize = fromIntegral $ sizeOfRawData b

data Section = Section
  { sHeader :: SectionHeader
  , sFlags :: [ShFlag]
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
