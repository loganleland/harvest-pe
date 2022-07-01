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
  { machine :: Either Word16 Machine
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
  return FileHeader { machine = typeMachine machine'
                    , numSection = numSection'
                    , timestamp = timestamp'
                    , ptrSymTab = ptrSymTab'
                    , numSyms = numSyms'
                    , sizeOptionalHeader = sizeOptionalHeader'
                    , characteristics = characteristics'
                    }

data Machine = IMAGE_FILE_MACHINE_UNKNOWN | IMAGE_FILE_MACHINE_AM33 | 
               IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM | 
               IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARMNT | 
               IMAGE_FILE_MACHINE_EBC | IMAGE_FILE_MACHINE_I386 | 
               IMAGE_FILE_MACHINE_IA64 | IMAGE_FILE_MACHINE_LOONGARCH32 | 
               IMAGE_FILE_MACHINE_LOONGARCH64 | IMAGE_FILE_MACHINE_M32R | 
               IMAGE_FILE_MACHINE_MIPS16 | IMAGE_FILE_MACHINE_MIPSFPU | 
               IMAGE_FILE_MACHINE_MIPSFPU16 | IMAGE_FILE_MACHINE_POWERPC | 
               IMAGE_FILE_MACHINE_POWERPCFP | IMAGE_FILE_MACHINE_R4000 | 
               IMAGE_FILE_MACHINE_RISCV32 | IMAGE_FILE_MACHINE_RISCV64 | 
               IMAGE_FILE_MACHINE_RISCV128 | IMAGE_FILE_MACHINE_SH3 | 
               IMAGE_FILE_MACHINE_SH3DSP | IMAGE_FILE_MACHINE_SH4 | 
               IMAGE_FILE_MACHINE_SH5 | IMAGE_FILE_MACHINE_THUMB
  deriving Show

typeMachine :: Word16 -> Either Word16 Machine
typeMachine a
  -- The content of this field is assumed to be applicable to any machine type 
  | a == 0 = Right IMAGE_FILE_MACHINE_UNKNOWN
  -- Matsushita AM33 
  | a == 467 = Right IMAGE_FILE_MACHINE_AM33
  -- x64 
  | a == 34404 = Right IMAGE_FILE_MACHINE_AMD64
  -- ARM little endian 
  | a == 448 = Right IMAGE_FILE_MACHINE_ARM
  -- ARM64 little endian 
  | a == 43620 = Right IMAGE_FILE_MACHINE_ARM64
  -- ARM Thumb-2 little endian 
  | a == 452 = Right IMAGE_FILE_MACHINE_ARMNT
  -- EFI byte code 
  | a == 3772 = Right IMAGE_FILE_MACHINE_EBC
  -- Intel 386 or later processors and compatible processors 
  | a == 332 = Right IMAGE_FILE_MACHINE_I386
  -- Intel Itanium processor family 
  | a == 512 = Right IMAGE_FILE_MACHINE_IA64
  -- LoongArch 32-bit processor family 
  | a == 25138 = Right IMAGE_FILE_MACHINE_LOONGARCH32
  -- LoongArch 64-bit processor family 
  | a == 25188 = Right IMAGE_FILE_MACHINE_LOONGARCH64
  -- Mitsubishi M32R little endian 
  | a == 36929 = Right IMAGE_FILE_MACHINE_M32R
  -- MIPS16 
  | a == 614 = Right IMAGE_FILE_MACHINE_MIPS16
  -- MIPS with FPU 
  | a == 870 = Right IMAGE_FILE_MACHINE_MIPSFPU
  -- MIPS16 with FPU 
  | a == 1126 = Right IMAGE_FILE_MACHINE_MIPSFPU16
  -- Power PC little endian 
  | a == 496 = Right IMAGE_FILE_MACHINE_POWERPC
  -- Power PC with floating point support 
  | a == 497 = Right IMAGE_FILE_MACHINE_POWERPCFP
  -- MIPS little endian 
  | a == 358 = Right IMAGE_FILE_MACHINE_R4000
  -- RISC-V 32-bit address space 
  | a == 20530 = Right IMAGE_FILE_MACHINE_RISCV32
  -- RISC-V 64-bit address space 
  | a == 20580 = Right IMAGE_FILE_MACHINE_RISCV64
  -- RISC-V 128-bit address space 
  | a == 20776 = Right IMAGE_FILE_MACHINE_RISCV128
  -- Hitachi SH3 
  | a == 418 = Right IMAGE_FILE_MACHINE_SH3
  -- Hitachi SH3 DSP 
  | a == 419 = Right IMAGE_FILE_MACHINE_SH3DSP
  -- Hitachi SH4 
  | a == 422 = Right IMAGE_FILE_MACHINE_SH4
  -- Hitachi SH5 
  | a == 424 = Right IMAGE_FILE_MACHINE_SH5
  -- Thumb 
  | a == 450 = Right IMAGE_FILE_MACHINE_THUMB
  | otherwise = Left a

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
