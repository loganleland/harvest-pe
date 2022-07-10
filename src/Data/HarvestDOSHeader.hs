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
-- Harvest (parse) PE DOS Header.
--
-----------------------------------------------------------------------------

module Data.HarvestDOSHeader
  where

import Data.Word
import qualified Data.Binary.Get as G
import qualified Data.ByteString.Lazy as BSL 
import Control.Monad (replicateM)

data DOSHeader = DOSHeader
  { e_magic :: BSL.ByteString
  , e_cblp :: Word16
  , e_cp :: Word16
  , e_crlc :: Word16
  , e_cparhdr :: Word16
  , e_minalloc :: Word16
  , e_maxalloc :: Word16
  , e_ss :: Word16
  , e_sp :: Word16
  , e_csum :: Word16
  , e_ip :: Word16
  , e_cs :: Word16
  , e_lfarlc :: Word16
  , e_ovno :: Word16
  , e_res :: [Word16]
  , e_oemid :: Word16
  , e_oeminfo :: Word16
  , e_res2 :: [Word16]
  , e_lfanew :: Word32
  }
  deriving Show

pprint :: DOSHeader -> String
pprint a =
  "======================\n" ++
  "===   DOS Header   ===\n" ++
  "======================\n" ++
  "Magic: " ++ show (e_magic a) ++ "\n" ++
  show (e_cblp a) ++ "\n" ++
  show (e_cp a) ++ "\n" ++
  show (e_crlc a) ++ "\n" ++
  show (e_cparhdr a) ++ "\n" ++
  show (e_minalloc a) ++ "\n" ++
  show (e_maxalloc a) ++ "\n" ++
  show (e_ss a) ++ "\n" ++
  show (e_sp a) ++ "\n" ++
  show (e_csum a) ++ "\n" ++
  show (e_ip a) ++ "\n" ++
  show (e_cs a) ++ "\n" ++
  show (e_lfarlc a) ++ "\n" ++
  show (e_ovno a) ++ "\n" ++
  show (e_res a) ++ "\n" ++
  show (e_oemid a) ++ "\n" ++
  show (e_oeminfo a) ++ "\n" ++
  show (e_res2 a) ++ "\n" ++
  show (e_lfanew a) ++ "\n"
 
harvest :: BSL.ByteString -> DOSHeader
harvest = G.runGet $ do
  e_magic' <- G.getLazyByteString 2
  e_cblp' <- G.getWord16le
  e_cp' <- G.getWord16le
  e_crlc' <- G.getWord16le
  e_cparhdr' <- G.getWord16le
  e_minalloc' <- G.getWord16le
  e_maxalloc' <- G.getWord16le
  e_ss' <- G.getWord16le
  e_sp' <- G.getWord16le
  e_csum' <- G.getWord16le
  e_ip' <- G.getWord16le
  e_cs' <- G.getWord16le
  e_lfarlc' <- G.getWord16le
  e_ovno' <- G.getWord16le
  e_res' <- replicateM 4 G.getWord16le
  e_oemid' <- G.getWord16le
  e_oeminfo' <- G.getWord16le
  e_res2' <- replicateM 10 G.getWord16le
  e_lfanew' <- G.getWord32le
  return DOSHeader { e_magic = e_magic'
                   , e_cblp = e_cblp'
                   , e_cp = e_cp'
                   , e_crlc = e_crlc'
                   , e_cparhdr = e_cparhdr'
                   , e_minalloc = e_minalloc'
                   , e_maxalloc = e_maxalloc'
                   , e_ss = e_ss'
                   , e_sp = e_sp'
                   , e_csum = e_csum'
                   , e_ip = e_ip'
                   , e_cs = e_cs'
                   , e_lfarlc = e_lfarlc'
                   , e_ovno = e_ovno'
                   , e_res = e_res'
                   , e_oemid = e_oemid'
                   , e_oeminfo = e_oeminfo'
                   , e_res2 = e_res2'
                   , e_lfanew = e_lfanew'
                   }
