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
-- Harvest (parse) PE NT Headers
--
-----------------------------------------------------------------------------

module Data.HarvestNTHeader
  where

import Data.Word
import qualified Data.Binary.Get as G
import qualified Data.ByteString.Lazy as BSL 
import Control.Monad (replicateM)

data FileHeader = FileHeader
  { machine :: Word16
  , numSection :: Word16
  , timestamp :: Word32
  , ptrSymTab :: Word32
  , numSyms :: Word32
  , sizeOptionalHeader :: Word16
  , characteristics :: Word16
  }
  deriving Show

harvestFileHeader :: Int -> BSL.ByteString -> FileHeader
harvestFileHeader a = G.runGet $ do
  G.skip a
  machine' <- G.getWord16le
  numSection' <- G.getWord16le
  timestamp' <- G.getWord32le
  ptrSymTab' <- G.getWord32le
  numSyms' <- G.getWord32le
  sizeOptionalHeader' <- G.getWord16le
  characteristics' <- G.getWord16le
  return FileHeader { machine = machine'
                    , numSection = numSection'
                    , timestamp = timestamp'
                    , ptrSymTab = ptrSymTab'
                    , numSyms = numSyms'
                    , sizeOptionalHeader = sizeOptionalHeader'
                    , characteristics = characteristics'
                    }

data DataDirectory = DataDirectory { virtualAddress :: Word32
                                   , size :: Word32
                                   }
  deriving Show

harvestDataDirectory :: G.Get DataDirectory
harvestDataDirectory = do
  virtAddr <- G.getWord32le
  size' <- G.getWord32le
  return DataDirectory { virtualAddress = virtAddr
                       , size = size'
                       }

data OptHeader = OptHeader
  { --16 (0x10) if PE, 32 (0x20) for PEPlus
    optMagic :: Word16
  , majorLinkerVersion :: Word8
  , minorLinkerVersion :: Word8
  , sizeOfCode :: Word32
  , sizeOfInitializedData :: Word32
  , sizeOfUninitializedData :: Word32
  , addressOfEntryPoint :: Word32
  , baseOfCode :: Word32
  , baseOfData :: Word32
  , imageBase :: Word32
  , sectionAlignment :: Word32
  , fileAlignment :: Word32
  , majorOperatingSystemVersion :: Word16
  , minorOperatingSystemVersion :: Word16
  , majorImageVersion :: Word16
  , minorImageVersion :: Word16
  , majorSubsystemVersion :: Word16
  , minorSubsystemVersion :: Word16
  , win32VersionValue :: Word32
  , sizeOfImage :: Word32
  , sizeOfHeaders :: Word32
  , checkSum :: Word32
  , subsystem :: Word16
  , dllCharacteristics :: Word16
  , sizeOfStackReserve :: Either Word32 Word64
  , sizeOfStackCommit :: Either Word32 Word64
  , sizeOfHeapReserve :: Either Word32 Word64
  , sizeOfHeapCommit :: Either Word32 Word64
  , loaderFlags :: Word32
  , numberOfRvaAndSizes :: Word32
  , dataDirectory :: [DataDirectory]
  }
  deriving Show

harvestOptHeader :: Int -> BSL.ByteString -> OptHeader
harvestOptHeader a = G.runGet $ do
  G.skip a
  optMagic' <- G.getWord16le
  majorLinkerVersion' <- G.getWord8
  minorLinkerVersion' <- G.getWord8
  sizeOfCode' <- G.getWord32le
  sizeOfInitializedData' <- G.getWord32le
  sizeOfUninitializedData' <- G.getWord32le
  addressOfEntryPoint' <- G.getWord32le
  baseOfCode' <- G.getWord32le
  baseOfData' <- G.getWord32le
  imageBase' <- G.getWord32le
  sectionAlignment' <- G.getWord32le
  fileAlignment' <- G.getWord32le
  majorOperatingSystemVersion' <- G.getWord16le
  minorOperatingSystemVersion' <- G.getWord16le
  majorImageVersion' <- G.getWord16le
  minorImageVersion' <- G.getWord16le
  majorSubsystemVersion' <- G.getWord16le
  minorSubsystemVersion' <- G.getWord16le
  win32VersionValue' <- G.getWord32le
  sizeOfImage' <- G.getWord32le
  sizeOfHeaders' <- G.getWord32le
  checkSum' <- G.getWord32le
  subsystem' <- G.getWord16le
  dllCharacteristics' <- G.getWord16le
  res <- case (fromIntegral optMagic') of
    267 -> do
      sizeOfStackReserve' <- G.getWord32le
      sizeOfStackCommit' <- G.getWord32le
      sizeOfHeapReserve' <- G.getWord32le
      sizeOfHeapCommit' <- G.getWord32le
      loaderFlags' <- G.getWord32le
      numberOfRvaAndSizes' <- G.getWord32le
      dataDirectory' <- replicateM 16 harvestDataDirectory
      return OptHeader { optMagic = optMagic'
                       , majorLinkerVersion = majorLinkerVersion'
                       , minorLinkerVersion = minorLinkerVersion'
                       , sizeOfCode = sizeOfCode'
                       , sizeOfInitializedData = sizeOfInitializedData'
                       , sizeOfUninitializedData = sizeOfUninitializedData'
                       , addressOfEntryPoint = addressOfEntryPoint'
                       , baseOfCode = baseOfCode'
                       , baseOfData = baseOfData'
                       , imageBase = imageBase'
                       , sectionAlignment = sectionAlignment'
                       , fileAlignment = fileAlignment'
                       , majorOperatingSystemVersion = majorOperatingSystemVersion'
                       , minorOperatingSystemVersion = minorOperatingSystemVersion'
                       , majorImageVersion = majorImageVersion'
                       , minorImageVersion = minorImageVersion'
                       , majorSubsystemVersion = majorSubsystemVersion'
                       , minorSubsystemVersion = minorSubsystemVersion'
                       , win32VersionValue = win32VersionValue'
                       , sizeOfImage = sizeOfImage'
                       , sizeOfHeaders = sizeOfHeaders'
                       , checkSum = checkSum'
                       , subsystem = subsystem'
                       , dllCharacteristics = dllCharacteristics'
                       , sizeOfStackReserve = Left sizeOfStackReserve'
                       , sizeOfStackCommit = Left sizeOfStackCommit'
                       , sizeOfHeapReserve = Left sizeOfHeapReserve'
                       , sizeOfHeapCommit = Left sizeOfHeapCommit'
                       , loaderFlags = loaderFlags'
                       , numberOfRvaAndSizes = numberOfRvaAndSizes'
                       , dataDirectory = dataDirectory'
                       }
    523 -> do
        sizeOfStackReserve' <- G.getWord64le
        sizeOfStackCommit' <- G.getWord64le
        sizeOfHeapReserve' <- G.getWord64le
        sizeOfHeapCommit' <- G.getWord64le
        loaderFlags' <- G.getWord32le
        numberOfRvaAndSizes' <- G.getWord32le
        dataDirectory' <- replicateM 16 harvestDataDirectory
        return OptHeader { optMagic = optMagic'
                         , majorLinkerVersion = majorLinkerVersion'
                         , minorLinkerVersion = minorLinkerVersion'
                         , sizeOfCode = sizeOfCode'
                         , sizeOfInitializedData = sizeOfInitializedData'
                         , sizeOfUninitializedData = sizeOfUninitializedData'
                         , addressOfEntryPoint = addressOfEntryPoint'
                         , baseOfCode = baseOfCode'
                         , baseOfData = baseOfData'
                         , imageBase = imageBase'
                         , sectionAlignment = sectionAlignment'
                         , fileAlignment = fileAlignment'
                         , majorOperatingSystemVersion = majorOperatingSystemVersion'
                         , minorOperatingSystemVersion = minorOperatingSystemVersion'
                         , majorImageVersion = majorImageVersion'
                         , minorImageVersion = minorImageVersion'
                         , majorSubsystemVersion = majorSubsystemVersion'
                         , minorSubsystemVersion = minorSubsystemVersion'
                         , win32VersionValue = win32VersionValue'
                         , sizeOfImage = sizeOfImage'
                         , sizeOfHeaders = sizeOfHeaders'
                         , checkSum = checkSum'
                         , subsystem = subsystem'
                         , dllCharacteristics = dllCharacteristics'
                         , sizeOfStackReserve = Right sizeOfStackReserve'
                         , sizeOfStackCommit = Right sizeOfStackCommit'
                         , sizeOfHeapReserve = Right sizeOfHeapReserve'
                         , sizeOfHeapCommit = Right sizeOfHeapCommit'
                         , loaderFlags = loaderFlags'
                         , numberOfRvaAndSizes = numberOfRvaAndSizes'
                         , dataDirectory = dataDirectory'
                         }
    other -> fail $ "Cannot derive 32-bit or 64-bit: " ++ show other
  return res

harvest :: Int -> BSL.ByteString -> NTHeader
harvest a b = flip G.runGet b $ do
  G.skip a
  signature' <- G.getWord32le
  let fHeader' = harvestFileHeader (a+4) b
  let oHeader' = harvestOptHeader (a+4+20) b
  return NTHeader { signature = signature'
                  , fHeader = fHeader'
                  , optHeader = oHeader'
                  }


data NTHeader = NTHeader
  { signature :: Word32
  , fHeader :: FileHeader
  , optHeader :: OptHeader
  }
  deriving Show
