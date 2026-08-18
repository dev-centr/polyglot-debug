//===-- ObjectFilePolyglot.cpp -----------------------------------*- C++ -*-===//
//
// Chord-scoring ObjectFile plugin for Actually Portable Executable and
// other multi-magic binaries. Intended for llvm-project/lldb.
//
// License: Apache-2.0 WITH LLVM-exception once in-tree; MIT in this repo.
//===----------------------------------------------------------------------===//

#include "ObjectFilePolyglot.h"

#include "lldb/Core/Module.h"
#include "lldb/Core/ModuleSpec.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Host/FileSystem.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/DataBuffer.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/LLDBLog.h"

#include <algorithm>
#include <vector>

using namespace lldb;
using namespace lldb_private;

LLDB_PLUGIN_DEFINE(ObjectFilePolyglot)

namespace {

constexpr uint8_t kApeMz[8] = {'M', 'Z', 'q', 'F', 'p', 'D', '=', '\''};
constexpr uint8_t kApeUnix[8] = {'j', 'a', 'r', 't', 's', 'r', '=', '\''};

bool LooksLikeAPE(DataExtractor &data) {
  if (data.GetByteSize() < 8)
    return false;
  uint8_t mag[8] = {};
  lldb::offset_t o = 0;
  for (int i = 0; i < 8; ++i)
    mag[i] = data.GetU8(&o);
  return std::equal(std::begin(kApeMz), std::end(kApeMz), mag) ||
         std::equal(std::begin(kApeUnix), std::end(kApeUnix), mag);
}

// First-match is the bug. Survey every registered creator that can parse
// a prefix of this buffer, then keep hits above a floor.
std::vector<ChordHit> Survey(const lldb::DataBufferSP &data_sp,
                             lldb::offset_t data_offset,
                             const FileSpec *file, lldb::offset_t file_offset,
                             lldb::offset_t length) {
  std::vector<ChordHit> hits;
  if (!data_sp)
    return hits;

  DataExtractor data(data_sp, lldb::eByteOrderLittle, 8);
  data.SetAddressByteSize(8);

  // Probe the well-known magics ourselves so we do not depend on plugin
  // registration order. Real in-tree wiring should iterate PluginManager's
  // ObjectFile create callbacks and call a new Score() API on each.
  auto add = [&](uint32_t score, const char *name) {
    ChordHit h;
    h.create = nullptr;
    h.score = score;
    h.plugin_name.SetCString(name);
    hits.push_back(h);
  };

  if (data.GetByteSize() >= 2 && data.GetU8(&data_offset) == 'M') {
    data_offset = 0;
    if (data.GetU8(&data_offset) == 'Z')
      add(LooksLikeAPE(data) ? 40 : 90, "pe-coff");
  }
  data_offset = 0;
  if (LooksLikeAPE(data))
    add(95, "ape-stub");

  // ELF at 0, or later once assimilated. Also scan first 8k for 0x7fELF.
  for (lldb::offset_t i = 0; i + 4 <= std::min<lldb::offset_t>(data.GetByteSize(), 8192); ++i) {
    lldb::offset_t o = i;
    if (data.GetU8(&o) == 0x7f && data.GetU8(&o) == 'E' && data.GetU8(&o) == 'L' &&
        data.GetU8(&o) == 'F') {
      add(i == 0 ? 90 : 70, "elf");
      break;
    }
  }

  uint32_t m = 0;
  lldb::offset_t o = 0;
  m = data.GetU32(&o);
  if (m == 0xfeedfacf || m == 0xcffaedfe || m == 0xcafebabe || m == 0xbebafeca)
    add(90, "mach-o");

  return hits;
}

} // namespace

void ObjectFilePolyglot::Initialize() {
  PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                GetPluginDescriptionStatic(), CreateInstance,
                                CreateMemoryInstance, GetModuleSpecifications);
}

void ObjectFilePolyglot::Terminate() {
  PluginManager::UnregisterPlugin(CreateInstance);
}

ObjectFile *ObjectFilePolyglot::CreateInstance(
    const ModuleSP &module_sp, DataBufferSP data_sp, lldb::offset_t data_offset,
    const FileSpec *file, lldb::offset_t file_offset, lldb::offset_t length) {
  if (!data_sp)
    return nullptr;
  DataExtractor data(data_sp, lldb::eByteOrderLittle, 8);
  auto hits = Survey(data_sp, data_offset, file, file_offset, length);
  unsigned high = 0;
  for (const auto &h : hits)
    if (h.score >= 50)
      ++high;
  // Only claim ownership when a chord exists (APE + PE, PE + ELF, ...).
  if (high < 2 && !LooksLikeAPE(data))
    return nullptr;
  return new ObjectFilePolyglot(module_sp, data_sp, data_offset, file,
                                file_offset, length, std::move(hits));
}

ObjectFile *ObjectFilePolyglot::CreateMemoryInstance(
    const ModuleSP &module_sp, WritableDataBufferSP data_sp,
    const ProcessSP &process_sp, lldb::addr_t header_addr) {
  return nullptr; // live-process path: attach after bootstrap snapshot
}

size_t ObjectFilePolyglot::GetModuleSpecifications(
    const FileSpec &file, DataBufferSP &data_sp, lldb::offset_t data_offset,
    lldb::offset_t file_offset, lldb::offset_t length, ModuleSpecList &specs) {
  auto hits = Survey(data_sp, data_offset, &file, file_offset, length);
  if (hits.size() < 2)
    return 0;
  ModuleSpec spec(file);
  spec.GetArchitecture().SetTriple("unknown-unknown-unknown");
  specs.Append(spec);
  return 1;
}

ObjectFilePolyglot::ObjectFilePolyglot(
    const ModuleSP &module_sp, DataBufferSP data_sp, lldb::offset_t data_offset,
    const FileSpec *file, lldb::offset_t offset, lldb::offset_t length,
    std::vector<ChordHit> hits)
    : ObjectFile(module_sp, file, offset, length, data_sp, data_offset),
      m_hits(std::move(hits)) {}

bool ObjectFilePolyglot::ParseHeader() {
  // Project the slice that matches the process plugin's OS.
  ArchSpec proc;
  if (ModuleSP mod = GetModule()) {
    proc = mod->GetArchitecture();
  }
  ConstString want = PickSlice(proc);
  m_active = want;
  return true;
}

ConstString ObjectFilePolyglot::PickSlice(const ArchSpec &proc) const {
  const llvm::Triple &t = proc.GetTriple();
  if (t.isOSDarwin())
    return ConstString("mach-o");
  if (t.isOSWindows())
    return ConstString("pe-coff");
  if (t.isOSBinFormatELF() || t.isOSLinux() || t.isOSFreeBSD() || t.isOSNetBSD() ||
      t.isOSOpenBSD())
    return ConstString("elf");
  // No process yet: prefer APE stub so GDB/LLDB do not map PE RVAs on Linux.
  return ConstString("ape-stub");
}

uint32_t ObjectFilePolyglot::GetAddressByteSize() const { return 8; }

ArchSpec ObjectFilePolyglot::GetArchitecture() {
  ArchSpec a;
  a.SetTriple("x86_64-unknown-linux-gnu");
  return a;
}

void ObjectFilePolyglot::CreateSections(SectionList &unified) {
  // Delegate to the winning concrete plugin once PluginManager exposes
  // CreateInstanceByName. Until then this plugin only prevents PE-on-Linux.
  (void)unified;
}

bool ObjectFilePolyglot::SetLoadAddress(Target &target, lldb::addr_t value,
                                        bool value_is_offset) {
  return false;
}

Symtab *ObjectFilePolyglot::GetSymtab() { return nullptr; }

bool ObjectFilePolyglot::IsStripped() { return true; }

Type ObjectFilePolyglot::CalculateType() { return eTypeExecutable; }

Strata ObjectFilePolyglot::CalculateStrata() { return eStrataUser; }
