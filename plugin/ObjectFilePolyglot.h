//===-- ObjectFilePolyglot.h -------------------------------------*- C++ -*-===//
#ifndef LLDB_SOURCE_PLUGINS_OBJECTFILE_POLYGLOT_OBJECTFILEPOLYGLOT_H
#define LLDB_SOURCE_PLUGINS_OBJECTFILE_POLYGLOT_OBJECTFILEPOLYGLOT_H

#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Utility/ArchSpec.h"

#include <vector>

namespace lldb_private {

struct ChordHit {
  ObjectFileCreateInstance create = nullptr;
  uint32_t score = 0;
  ConstString plugin_name;
};

/// Meta ObjectFile: owns a file when two or more format plugins score a hit.
class ObjectFilePolyglot : public ObjectFile {
public:
  static void Initialize();
  static void Terminate();
  static llvm::StringRef GetPluginNameStatic() { return "polyglot"; }
  static llvm::StringRef GetPluginDescriptionStatic() {
    return "Polyglot / APE object file (chord-scored PE+ELF+Mach-O)";
  }
  static ObjectFile *CreateInstance(const lldb::ModuleSP &module_sp,
                                    lldb::DataBufferSP data_sp,
                                    lldb::offset_t data_offset,
                                    const FileSpec *file,
                                    lldb::offset_t file_offset,
                                    lldb::offset_t length);
  static ObjectFile *CreateMemoryInstance(const lldb::ModuleSP &module_sp,
                                          lldb::WritableDataBufferSP data_sp,
                                          const lldb::ProcessSP &process_sp,
                                          lldb::addr_t header_addr);
  static size_t GetModuleSpecifications(const FileSpec &file,
                                        lldb::DataBufferSP &data_sp,
                                        lldb::offset_t data_offset,
                                        lldb::offset_t file_offset,
                                        lldb::offset_t length,
                                        ModuleSpecList &specs);

  llvm::StringRef GetPluginName() override { return GetPluginNameStatic(); }

  bool ParseHeader() override;
  ArchSpec GetArchitecture() override;
  void CreateSections(SectionList &unified_section_list) override;
  bool SetLoadAddress(Target &target, lldb::addr_t value,
                      bool value_is_offset) override;
  Symtab *GetSymtab() override;
  bool IsStripped() override;
  Type CalculateType() override;
  Strata CalculateStrata() override;
  uint32_t GetAddressByteSize() const override;
  lldb::ByteOrder GetByteOrder() const override {
    return lldb::eByteOrderLittle;
  }

private:
  ObjectFilePolyglot(const lldb::ModuleSP &module_sp, lldb::DataBufferSP data_sp,
                     lldb::offset_t data_offset, const FileSpec *file,
                     lldb::offset_t offset, lldb::offset_t length,
                     std::vector<ChordHit> hits);

  ConstString PickSlice(const ArchSpec &proc) const;

  std::vector<ChordHit> m_hits;
  ConstString m_active;
};

} // namespace lldb_private

#endif
