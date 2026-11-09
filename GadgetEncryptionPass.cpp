#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "GadgetEncryptionPass.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <windows.h>

using namespace llvm;

llvm::cl::opt<bool> GadgetEncryptionEnable("obfgadgetencryption", llvm::cl::init(true), llvm::cl::desc("Master Toggle"));

static constexpr unsigned PerFnCap = 32;
static constexpr unsigned MinBitwidth = 8;
static constexpr unsigned MaxBitwidth = 64;
static constexpr bool SkipLoopHdrs = true;
static constexpr bool SkipGEPIndices = false;
static constexpr unsigned MinInstances = 5;
static constexpr const char* ScanDir = "C:\\Windows\\System32";
static constexpr unsigned MaxShapesPerSite = 6;

static const char* const Hosts[] = {
    "kernel32.dll", "kernelbase.dll", "ntdll.dll",
};
static constexpr unsigned HostsCount = sizeof(Hosts) / sizeof(Hosts[0]);

struct ShapeMatch
{
    uint64_t r;
    unsigned size;
};

static inline uint32_t Rd32(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

static inline uint64_t Rd64(const uint8_t* p)
{
    return static_cast<uint64_t>(Rd32(p)) | (static_cast<uint64_t>(Rd32(p + 4)) << 32);
}

static std::optional<ShapeMatch> TryMatchAt(const uint8_t* p, size_t n)
{
    if (n >= 11 && p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xC3)
        return ShapeMatch{Rd64(p + 2), 11};
    if (n >= 8 && p[0] == 0x48 && p[1] == 0xC7 && p[2] == 0xC0 && p[7] == 0xC3)
    {
        if (p[3] == 0xFF && p[4] == 0xFF && p[5] == 0xFF && p[6] == 0xFF)
            return ShapeMatch{0xFFFFFFFFFFFFFFFFULL, 8};
        int32_t imm = static_cast<int32_t>(Rd32(p + 3));
        return ShapeMatch{static_cast<uint64_t>(static_cast<int64_t>(imm)), 8};
    }
    if (n >= 6 && p[0] == 0xB8 && p[5] == 0xC3)
        return ShapeMatch{static_cast<uint64_t>(Rd32(p + 1)), 6};
    if (n >= 5 && p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xC8 && p[3] == 0xFF && p[4] == 0xC3)
        return ShapeMatch{0xFFFFFFFFFFFFFFFFULL, 5};
    if (n >= 4)
    {
        if (p[0] == 0x48 && p[1] == 0x31 && p[2] == 0xC0 && p[3] == 0xC3) return ShapeMatch{0, 4};
        if (p[0] == 0x48 && p[1] == 0x33 && p[2] == 0xC0 && p[3] == 0xC3) return ShapeMatch{0, 4};
        if (p[0] == 0x48 && p[1] == 0x29 && p[2] == 0xC0 && p[3] == 0xC3) return ShapeMatch{0, 4};
        if (p[0] == 0x83 && p[1] == 0xC8 && p[2] == 0xFF && p[3] == 0xC3) return ShapeMatch{0xFFFFFFFFULL, 4};
    }
    if (n >= 3)
    {
        if (p[0] == 0x33 && p[1] == 0xC0 && p[2] == 0xC3) return ShapeMatch{0, 3};
        if (p[0] == 0x31 && p[1] == 0xC0 && p[2] == 0xC3) return ShapeMatch{0, 3};
        if (p[0] == 0x29 && p[1] == 0xC0 && p[2] == 0xC3) return ShapeMatch{0, 3};
    }
    return std::nullopt;
}

struct GadgetEntry
{
    std::string host;
    uint32_t rva;
    std::vector<uint8_t> bytes;
};

struct GadgetBank
{
   
    std::unordered_map<uint64_t, std::vector<GadgetEntry>> byr;
  
    std::unordered_map<uint64_t, std::vector<std::vector<uint8_t>>> shapesbyr;
    bool scanned = false;
};

static GadgetBank Bank;
static std::mutex BankMutex;
static std::unordered_set<Value*> OurEmits;

static bool ScanOneDLL(const std::string& dir, const std::string& host, std::unordered_map<uint64_t, std::vector<GadgetEntry>>& outbyr)
{
    std::string path = dir + "\\" + host;
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize n = f.tellg();
    if (n < static_cast<std::streamsize>(sizeof(IMAGE_DOS_HEADER))) return false;
    std::vector<uint8_t> bytes(static_cast<size_t>(n));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(bytes.data()), n);
    if (!f) return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > bytes.size()) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

    auto* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned s = 0; s < nt->FileHeader.NumberOfSections; ++s)
    {
        const auto& sec = sections[s];
        if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        size_t off = sec.PointerToRawData;
        size_t sz = sec.SizeOfRawData;
        if (off == 0 || sz == 0 || off + sz > bytes.size()) continue;

        const uint8_t* p = bytes.data() + off;
        if (sz < 3) continue;
        const size_t stop = sz - 2;
        for (size_t i = 0; i < stop; ++i)
        {
            auto m = TryMatchAt(p + i, sz - i);
            if (m)
            {
                GadgetEntry e;
                e.host = host;
                e.rva = sec.VirtualAddress + static_cast<uint32_t>(i);
                e.bytes.assign(p + i, p + i + m->size);
                outbyr[m->r].push_back(std::move(e));
            }
        }
    }
    return true;
}

static void PopulateBank()
{
    std::lock_guard<std::mutex> lock(BankMutex);
    if (Bank.scanned) return;

    std::vector<std::unordered_map<uint64_t, std::vector<GadgetEntry>>> perhost;
    perhost.resize(HostsCount);

    std::vector<const char*> failedhosts;
    unsigned scannedcount = 0;
    for (unsigned hi = 0; hi < HostsCount; ++hi)
    {
        if (ScanOneDLL(ScanDir, Hosts[hi], perhost[hi])) ++scannedcount;
        else failedhosts.push_back(Hosts[hi]);
    }

    
    std::unordered_set<uint64_t> allr;
    for (auto& m : perhost)
    {
        for (auto& [r, v] : m) allr.insert(r);
    }

    for (uint64_t r : allr)
    {
        bool qualified = false;
        for (auto& m : perhost)
        {
            auto it = m.find(r);
            if (it != m.end() && it->second.size() >= MinInstances)
            {
                qualified = true;
                break;
            }
        }
        if (!qualified) continue;

        auto& pool = Bank.byr[r];
        for (auto& m : perhost)
        {
            auto it = m.find(r);
            if (it != m.end()) pool.insert(pool.end(), it->second.begin(), it->second.end());
        }
    }

    for (auto& [r, pool] : Bank.byr)
    {
        std::vector<std::pair<std::vector<uint8_t>, unsigned>> freq;
        for (const auto& e : pool)
        {
            bool found = false;
            for (auto& fs : freq)
            {
                if (fs.first == e.bytes)
                {
                    ++fs.second;
                    found = true;
                    break;
                }
            }
            if (!found) freq.push_back({e.bytes, 1});
        }
        std::stable_sort(freq.begin(), freq.end(), [](const auto& a, const auto& b)
        {
            return a.second > b.second;
        });
        auto& outshapes = Bank.shapesbyr[r];
        for (auto& fs : freq)
        {
            if (outshapes.size() >= MaxShapesPerSite) break;
            outshapes.push_back(std::move(fs.first));
        }
    }

    std::mt19937 rng{std::random_device{}()};
    for (auto& [r, entries] : Bank.byr) std::shuffle(entries.begin(), entries.end(), rng);

    Bank.scanned = true;

    uint64_t pooledrvas = 0;
    for (auto& [r, pool] : Bank.byr) pooledrvas += pool.size();
    std::cout << "[GadgetEncryption] scanner: " << scannedcount << "/" << HostsCount
              << " DLLs scanned, " << Bank.byr.size() << " R values, "
              << pooledrvas << " pooled gadget RVAs\n";
    if (!failedhosts.empty())
    {
        std::cout << "[GadgetEncryption] scanner: failed to load:";
        for (const char* h : failedhosts) std::cout << " " << h;
        std::cout << "\n";
    }
    std::cout.flush();
}

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return false;

    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;

    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;

        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;

        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;

        if (cds->getAsCString() == tag) return true;
    }
    return false;
}

static bool HasGadgetEncAnnotation(Function& f)
{
    return HasAnnotationTag(f, "gadgetenc");
}

static bool HasNoGadgetEncAnnotation(Function& f)
{
    return HasAnnotationTag(f, "nogadgetenc");
}

static bool WantsGadgetEnc(Function& f)
{
    if (HasNoGadgetEncAnnotation(f)) return false;
    return HasGadgetEncAnnotation(f);
}

static std::string SanitizeForSymbol(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(std::isalnum(static_cast<unsigned char>(c)) ? c : '_');
    return out;
}

struct ModuleContext
{
    FunctionCallee gmhdecl;
    std::unordered_map<std::string, Function*> hostbasehelpers;
    std::unordered_map<std::string, GlobalVariable*> hostnamegvs;
    Function* scanhelper = nullptr;
    unsigned sitecounter = 0;
};

static FunctionCallee GetModuleHandleADecl(Module& m)
{
    LLVMContext& c = m.getContext();
    PointerType* ptrty = PointerType::get(c, 0);
    FunctionType* ft = FunctionType::get(ptrty, {ptrty}, false);
    FunctionCallee fc = m.getOrInsertFunction("GetModuleHandleA", ft);
    if (Function* f = dyn_cast<Function>(fc.getCallee()))
    {
        f->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
    }
    return fc;
}

static GlobalVariable* GetOrEmitHostNameGV(Module& m, ModuleContext& ctx, const std::string& host)
{
    auto it = ctx.hostnamegvs.find(host);
    if (it != ctx.hostnamegvs.end()) return it->second;

    LLVMContext& c = m.getContext();
    Constant* data = ConstantDataArray::getString(c, host, true);
    GlobalVariable* gv = new GlobalVariable(m, data->getType(), true, GlobalValue::PrivateLinkage, data, "__ge_hostname_" + SanitizeForSymbol(host));
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    ctx.hostnamegvs[host] = gv;
    return gv;
}

static Function* GetOrEmitHostBaseHelper(Module& m, ModuleContext& ctx, const std::string& host)
{
    auto it = ctx.hostbasehelpers.find(host);
    if (it != ctx.hostbasehelpers.end()) return it->second;

    LLVMContext& c = m.getContext();
    Type* i64 = Type::getInt64Ty(c);

    GlobalVariable* cache = new GlobalVariable(m, i64, false, GlobalValue::PrivateLinkage, ConstantInt::get(i64, 0), "__ge_cache_" + SanitizeForSymbol(host));
    cache->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    GlobalVariable* namegv = GetOrEmitHostNameGV(m, ctx, host);

    FunctionType* ft = FunctionType::get(i64, {}, false);
    Function* f = Function::Create(ft, GlobalValue::InternalLinkage, "__ge_hostbase_" + SanitizeForSymbol(host), &m);
    f->addFnAttr(Attribute::NoInline);
    f->addFnAttr(Attribute::NoUnwind);
    f->addFnAttr(Attribute::WillReturn);

    BasicBlock* entrybb = BasicBlock::Create(c, "Entry", f);
    BasicBlock* resolvebb = BasicBlock::Create(c, "Resolve", f);
    BasicBlock* donebb = BasicBlock::Create(c, "Done", f);

    IRBuilder<> b(entrybb);
    Value* cached = b.CreateLoad(i64, cache, "Cached");
    Value* hit = b.CreateICmpNE(cached, ConstantInt::get(i64, 0), "Hit");
    b.CreateCondBr(hit, donebb, resolvebb);

    b.SetInsertPoint(resolvebb);
    Value* hname = b.CreateGEP(namegv->getValueType(), namegv, {ConstantInt::get(i64, 0), ConstantInt::get(i64, 0)}, "HName");
    CallInst* hcall = b.CreateCall(ctx.gmhdecl, {hname}, "HModule");
    hcall->setDoesNotThrow();
    Value* base = b.CreatePtrToInt(hcall, i64, "Base");
    b.CreateStore(base, cache);
    b.CreateBr(donebb);

    b.SetInsertPoint(donebb);
    PHINode* phi = b.CreatePHI(i64, 2, "BasePhi");
    phi->addIncoming(cached, entrybb);
    phi->addIncoming(base, resolvebb);
    b.CreateRet(phi);

    ctx.hostbasehelpers[host] = f;
    return f;
}

static Function* GetOrEmitScanHelper(Module& m, ModuleContext& ctx)
{
    if (ctx.scanhelper) return ctx.scanhelper;

    LLVMContext& c = m.getContext();
    Type* i8 = Type::getInt8Ty(c);
    Type* i16 = Type::getInt16Ty(c);
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    PointerType* ptrty = PointerType::get(c, 0);

    FunctionType* ft = FunctionType::get(i64, {i64, ptrty, ptrty, i32}, false);
    Function* f = Function::Create(ft, GlobalValue::InternalLinkage, "__ge_scan", &m);
    f->addFnAttr(Attribute::NoInline);
    f->addFnAttr(Attribute::NoUnwind);
    Argument* argbase = f->getArg(0);
    argbase->setName("Base");
    Argument* argshapes = f->getArg(1);
    argshapes->setName("Shapes");
    Argument* arglens = f->getArg(2);
    arglens->setName("Lens");
    Argument* argk = f->getArg(3);
    argk->setName("K");

    BasicBlock* entry = BasicBlock::Create(c, "Entry", f);
    BasicBlock* secloop = BasicBlock::Create(c, "SecLoop", f);
    BasicBlock* secbody = BasicBlock::Create(c, "SecBody", f);
    BasicBlock* secexec = BasicBlock::Create(c, "SecExec", f);
    BasicBlock* offloop = BasicBlock::Create(c, "OffLoop", f);
    BasicBlock* shapeloop = BasicBlock::Create(c, "ShapeLoop", f);
    BasicBlock* shapebody = BasicBlock::Create(c, "ShapeBody", f);
    BasicBlock* cmploop = BasicBlock::Create(c, "CmpLoop", f);
    BasicBlock* cmpbody = BasicBlock::Create(c, "CmpBody", f);
    BasicBlock* cmpcont = BasicBlock::Create(c, "CmpCont", f);
    BasicBlock* found = BasicBlock::Create(c, "Found", f);
    BasicBlock* shapecont = BasicBlock::Create(c, "ShapeCont", f);
    BasicBlock* offcont = BasicBlock::Create(c, "OffCont", f);
    BasicBlock* seccont = BasicBlock::Create(c, "SecCont", f);
    BasicBlock* notfound = BasicBlock::Create(c, "NotFound", f);

    IRBuilder<> b(entry);
    Value* bp = b.CreateIntToPtr(argbase, ptrty, "Bp");
    Value* lfaptr = b.CreateGEP(i8, bp, ConstantInt::get(i64, 60), "LfaPtr");
    Value* lfa = b.CreateLoad(i32, lfaptr, "ELfanew");
    Value* lfaz = b.CreateZExt(lfa, i64);
    Value* nt = b.CreateGEP(i8, bp, lfaz, "Nt");
    Value* nsptr = b.CreateGEP(i8, nt, ConstantInt::get(i64, 6), "NsPtr");
    Value* ns16 = b.CreateLoad(i16, nsptr, "Ns16");
    Value* ns = b.CreateZExt(ns16, i32, "NSections");
    Value* optptr = b.CreateGEP(i8, nt, ConstantInt::get(i64, 20), "OptPtr");
    Value* opt16 = b.CreateLoad(i16, optptr, "Opt16");
    Value* optz = b.CreateZExt(opt16, i64);
    Value* secbase = b.CreateGEP(i8, nt, ConstantInt::get(i64, 24), "SecBase");
    Value* sec = b.CreateGEP(i8, secbase, optz, "Sec");
    b.CreateBr(secloop);

    b.SetInsertPoint(secloop);
    PHINode* iphi = b.CreatePHI(i32, 2, "I");
    iphi->addIncoming(ConstantInt::get(i32, 0), entry);
    Value* icond = b.CreateICmpULT(iphi, ns, "ICond");
    b.CreateCondBr(icond, secbody, notfound);

    b.SetInsertPoint(secbody);
    Value* iz = b.CreateZExt(iphi, i64);
    Value* ix40 = b.CreateMul(iz, ConstantInt::get(i64, 40));
    Value* sptr = b.CreateGEP(i8, sec, ix40, "S");
    Value* chrpt = b.CreateGEP(i8, sptr, ConstantInt::get(i64, 36), "ChrPtr");
    Value* chr = b.CreateLoad(i32, chrpt, "Chr");
    Value* exec = b.CreateAnd(chr, ConstantInt::get(i32, 0x20000000), "Exec");
    Value* ise = b.CreateICmpNE(exec, ConstantInt::get(i32, 0), "IsExec");
    b.CreateCondBr(ise, secexec, seccont);

    b.SetInsertPoint(secexec);
    Value* rvapt = b.CreateGEP(i8, sptr, ConstantInt::get(i64, 12), "RvaPtr");
    Value* rvav = b.CreateLoad(i32, rvapt, "Rva");
    Value* rvaz = b.CreateZExt(rvav, i64);
    Value* vspt = b.CreateGEP(i8, sptr, ConstantInt::get(i64, 8), "VsPtr");
    Value* vsv = b.CreateLoad(i32, vspt, "Vs");
    Value* rspt = b.CreateGEP(i8, sptr, ConstantInt::get(i64, 16), "RsPtr");
    Value* rsv = b.CreateLoad(i32, rspt, "Rs");
    Value* vszero = b.CreateICmpEQ(vsv, ConstantInt::get(i32, 0));
    Value* vsize = b.CreateSelect(vszero, rsv, vsv, "Vsize");
    Value* vsz = b.CreateZExt(vsize, i64);
    Value* vsempty = b.CreateICmpEQ(vsz, ConstantInt::get(i64, 0), "VsEmpty");
    Value* data = b.CreateGEP(i8, bp, rvaz, "Data");
    b.CreateCondBr(vsempty, seccont, offloop);

    b.SetInsertPoint(offloop);
    PHINode* offphi = b.CreatePHI(i64, 2, "Off");
    offphi->addIncoming(ConstantInt::get(i64, 0), secexec);
    Value* offok = b.CreateICmpULT(offphi, vsz, "OffOk");
    b.CreateCondBr(offok, shapeloop, seccont);

    b.SetInsertPoint(shapeloop);
    PHINode* kphi = b.CreatePHI(i32, 2, "K");
    PHINode* cursorphi = b.CreatePHI(i32, 2, "Cursor");
    kphi->addIncoming(ConstantInt::get(i32, 0), offloop);
    cursorphi->addIncoming(ConstantInt::get(i32, 0), offloop);
    Value* kcond = b.CreateICmpULT(kphi, argk, "KCond");
    b.CreateCondBr(kcond, shapebody, offcont);

    b.SetInsertPoint(shapebody);
    Value* kz64 = b.CreateZExt(kphi, i64);
    Value* lenkptr = b.CreateGEP(i8, arglens, kz64, "LenKPtr");
    Value* lenk8 = b.CreateLoad(i8, lenkptr, "LenK8");
    Value* lenk32 = b.CreateZExt(lenk8, i32, "LenK32");
    Value* lenk64 = b.CreateZExt(lenk8, i64, "LenK64");
    Value* offplusl = b.CreateAdd(offphi, lenk64, "OffPlusL");
    Value* fits = b.CreateICmpULE(offplusl, vsz, "Fits");
    b.CreateCondBr(fits, cmploop, shapecont);

    b.SetInsertPoint(cmploop);
    PHINode* jphi = b.CreatePHI(i64, 2, "J");
    jphi->addIncoming(ConstantInt::get(i64, 0), shapebody);
    Value* jdone = b.CreateICmpUGE(jphi, lenk64, "JDone");
    b.CreateCondBr(jdone, found, cmpbody);

    b.SetInsertPoint(cmpbody);
    Value* offj = b.CreateAdd(offphi, jphi);
    Value* dptr = b.CreateGEP(i8, data, offj, "DPtr");
    Value* dbyte = b.CreateLoad(i8, dptr, "DByte");
    Value* cursor64 = b.CreateZExt(cursorphi, i64);
    Value* curplusj = b.CreateAdd(cursor64, jphi, "CurPlusJ");
    Value* sptr2 = b.CreateGEP(i8, argshapes, curplusj, "SPtr");
    Value* sbyte = b.CreateLoad(i8, sptr2, "SByte");
    Value* eq = b.CreateICmpEQ(dbyte, sbyte, "Eq");
    b.CreateCondBr(eq, cmpcont, shapecont);

    b.SetInsertPoint(cmpcont);
    Value* jnext = b.CreateAdd(jphi, ConstantInt::get(i64, 1));
    jphi->addIncoming(jnext, cmpcont);
    b.CreateBr(cmploop);

    b.SetInsertPoint(found);
    Value* foundptr = b.CreateGEP(i8, data, offphi, "FoundPtr");
    Value* foundabs = b.CreatePtrToInt(foundptr, i64, "FoundAbs");
    b.CreateRet(foundabs);

    b.SetInsertPoint(shapecont);
    Value* knext = b.CreateAdd(kphi, ConstantInt::get(i32, 1));
    Value* cursornext = b.CreateAdd(cursorphi, lenk32);
    kphi->addIncoming(knext, shapecont);
    cursorphi->addIncoming(cursornext, shapecont);
    b.CreateBr(shapeloop);

    b.SetInsertPoint(offcont);
    Value* offnext = b.CreateAdd(offphi, ConstantInt::get(i64, 1));
    offphi->addIncoming(offnext, offcont);
    b.CreateBr(offloop);

    b.SetInsertPoint(seccont);
    Value* inext = b.CreateAdd(iphi, ConstantInt::get(i32, 1));
    iphi->addIncoming(inext, seccont);
    b.CreateBr(secloop);

    b.SetInsertPoint(notfound);
    b.CreateRet(ConstantInt::get(i64, 0));

    ctx.scanhelper = f;
    return f;
}

static bool IsRewritableConstOp(Instruction& i, unsigned opidx)
{
    if (isa<PHINode>(i)) return false;
    if (isa<BranchInst>(i)) return false;
    if (isa<SwitchInst>(i)) return false;
    if (isa<IndirectBrInst>(i)) return false;
    if (isa<LandingPadInst>(i)) return false;
    if (isa<FuncletPadInst>(i)) return false;
    if (isa<DbgInfoIntrinsic>(i)) return false;

    if (auto* call = dyn_cast<CallBase>(&i))
    {
        if (opidx >= call->arg_size()) return false;
        if (call->paramHasAttr(opidx, Attribute::ImmArg)) return false;
        return true;
    }

    if (auto* gep = dyn_cast<GetElementPtrInst>(&i))
    {
        if (opidx == 0) return false;
        if (SkipGEPIndices) return false;
        auto gti = gep_type_begin(gep);
        auto end = gep_type_end(gep);
        for (unsigned k = 1; k < opidx && gti != end; ++k, ++gti) {}
        if (gti == end) return false;
        return gti.getStructTypeOrNull() == nullptr;
    }
    return true;
}

struct Rewrite
{
    Instruction* user;
    unsigned opidx;
    uint64_t origbits;
    Type* origtype;
};

static std::optional<uint64_t> PickR(const std::unordered_set<uint64_t>& fnused, std::mt19937& rng)
{
    if (Bank.byr.empty()) return std::nullopt;

    std::vector<uint64_t> unused;
    unused.reserve(Bank.byr.size());
    for (auto& [r, _] : Bank.byr)
    {
        if (!fnused.count(r)) unused.push_back(r);
    }

    if (!unused.empty())
    {
        std::uniform_int_distribution<size_t> d(0, unused.size() - 1);
        return unused[d(rng)];
    }

    std::vector<uint64_t> all;
    all.reserve(Bank.byr.size());
    for (auto& [r, _] : Bank.byr) all.push_back(r);
    std::uniform_int_distribution<size_t> d(0, all.size() - 1);
    return all[d(rng)];
}

static bool ProcessFunction(Function& f, ModuleContext& ctx, std::mt19937& rng)
{
    if (f.isDeclaration()) return false;

    DominatorTree dt;
    dt.recalculate(f);
    LoopInfo li;
    li.analyze(dt);

    std::vector<Rewrite> harvest;
    harvest.reserve(64);
    for (BasicBlock& bb : f)
    {
        
        if (SkipLoopHdrs)
        {
            Loop* l = li.getLoopFor(&bb);
            if (l && l->getHeader() == &bb) continue;
        }
        for (Instruction& i : bb)
        {
            if (OurEmits.count(&i)) continue;
            if (isa<IntrinsicInst>(&i)) continue;
            for (unsigned k = 0, e = i.getNumOperands(); k < e; ++k)
            {
                if (!IsRewritableConstOp(i, k)) continue;
                auto* ci = dyn_cast<ConstantInt>(i.getOperand(k));
                if (!ci) continue;
                unsigned bw = ci->getBitWidth();
                if (bw < MinBitwidth || bw > MaxBitwidth) continue;
                harvest.push_back({&i, k, ci->getZExtValue(), ci->getType()});
            }
        }
    }

    if (harvest.empty()) return false;

    std::shuffle(harvest.begin(), harvest.end(), rng);
    if (harvest.size() > PerFnCap) harvest.resize(PerFnCap);

    std::unordered_set<uint64_t> fnusedrs;

    LLVMContext& c = f.getContext();
    Type* i64 = Type::getInt64Ty(c);
    PointerType* ptrty = PointerType::get(c, 0);
    FunctionType* gadgett = FunctionType::get(i64, {}, false);

    unsigned siteshere = 0;

    for (const Rewrite& r : harvest)
    {
        auto ropt = PickR(fnusedrs, rng);
        if (!ropt) break;
        uint64_t rval = *ropt;
        fnusedrs.insert(rval);

        auto& pool = Bank.byr[rval];
        if (pool.empty()) continue;
        std::uniform_int_distribution<size_t> edist(0, pool.size() - 1);
        const GadgetEntry& entry = pool[edist(rng)];

        uint64_t enc = r.origbits ^ rval;

        Function* helper = GetOrEmitHostBaseHelper(*f.getParent(), ctx, entry.host);
        Function* scanner = GetOrEmitScanHelper(*f.getParent(), ctx);

        auto shapeit = Bank.shapesbyr.find(rval);
        if (shapeit == Bank.shapesbyr.end() || shapeit->second.empty()) continue;
        const auto& shapelist = shapeit->second;

        std::vector<uint8_t> packed;
        std::vector<uint8_t> lens;
        packed.reserve(shapelist.size() * 11);
        lens.reserve(shapelist.size());
        for (const auto& s : shapelist)
        {
            packed.insert(packed.end(), s.begin(), s.end());
            lens.push_back(static_cast<uint8_t>(s.size()));
        }

       
        Constant* shapesdata = ConstantDataArray::get(c, ArrayRef<uint8_t>(packed.data(), packed.size()));
        GlobalVariable* shapesgv = new GlobalVariable(*f.getParent(), shapesdata->getType(), true, GlobalValue::PrivateLinkage, shapesdata, "__ge_shapes_" + std::to_string(ctx.sitecounter));
        shapesgv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

        Constant* lensdata = ConstantDataArray::get(c, ArrayRef<uint8_t>(lens.data(), lens.size()));
        GlobalVariable* lensgv = new GlobalVariable(*f.getParent(), lensdata->getType(), true, GlobalValue::PrivateLinkage, lensdata, "__ge_shape_lens_" + std::to_string(ctx.sitecounter));
        lensgv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

       
        GlobalVariable* cachegv = new GlobalVariable(*f.getParent(), i64, false, GlobalValue::PrivateLinkage, ConstantInt::get(i64, 0), "__ge_cache_" + std::to_string(ctx.sitecounter));
        cachegv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        ++ctx.sitecounter;

        BasicBlock* origbb = r.user->getParent();
        BasicBlock* callbb = origbb->splitBasicBlock(r.user, "GECall");
        Instruction* splitterm = origbb->getTerminator();

        IRBuilder<> ob(splitterm);
        Value* cached = ob.CreateLoad(i64, cachegv, "GECached");
        Value* hit = ob.CreateICmpNE(cached, ConstantInt::get(i64, 0), "GEHit");

        BasicBlock* scanbb = BasicBlock::Create(c, "GEScan", &f, callbb);

        splitterm->eraseFromParent();
        BranchInst::Create(callbb, scanbb, hit, origbb);

        IRBuilder<> sb(scanbb);
        Value* base = sb.CreateCall(helper, {}, "GEBase");
        Constant* kc = ConstantInt::get(Type::getInt32Ty(c), static_cast<unsigned>(shapelist.size()));
        Value* found = sb.CreateCall(scanner, {base, shapesgv, lensgv, kc}, "GEFound");
        sb.CreateStore(found, cachegv);
        sb.CreateBr(callbb);

        IRBuilder<> cb(&*callbb->getFirstInsertionPt());
        PHINode* absphi = cb.CreatePHI(i64, 2, "GEAbs");
        absphi->addIncoming(cached, origbb);
        absphi->addIncoming(found, scanbb);
        Value* fp = cb.CreateIntToPtr(absphi, ptrty, "GEFP");
        CallInst* gc = cb.CreateCall(gadgett, fp, {}, "GER");
        gc->setDoesNotThrow();
        gc->addFnAttr(Attribute::WillReturn);
        Value* dec64 = cb.CreateXor(gc, ConstantInt::get(i64, enc), "GEDec64");

        Value* dec = dec64;
        if (!r.origtype->isIntegerTy(64)) dec = cb.CreateTrunc(dec64, r.origtype, "GEDec");

       
        if (auto* ins = dyn_cast<Instruction>(cached)) OurEmits.insert(ins);
        if (auto* ins = dyn_cast<Instruction>(hit)) OurEmits.insert(ins);
        if (auto* ins = dyn_cast<Instruction>(base)) OurEmits.insert(ins);
        if (auto* ins = dyn_cast<Instruction>(found)) OurEmits.insert(ins);
        OurEmits.insert(absphi);
        if (auto* ins = dyn_cast<Instruction>(fp)) OurEmits.insert(ins);
        OurEmits.insert(gc);
        if (auto* ins = dyn_cast<Instruction>(dec64)) OurEmits.insert(ins);
        if (dec != dec64)
        {
            if (auto* ins = dyn_cast<Instruction>(dec)) OurEmits.insert(ins);
        }

        r.user->setOperand(r.opidx, dec);
        ++siteshere;
    }

    return siteshere > 0;
}

bool RunGadgetEncryption(Module& m)
{
    if (!GadgetEncryptionEnable) return false;

    OurEmits.clear();

    PopulateBank();
    if (Bank.byr.empty()) return false;

    std::mt19937 rng{std::random_device{}()};

    ModuleContext ctx;
    ctx.gmhdecl = GetModuleHandleADecl(m);

    bool mutated = false;
    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (f.getName().starts_with("__ge_")) continue;

        if (!WantsGadgetEnc(f)) continue;

        if (ProcessFunction(f, ctx, rng)) mutated = true;
    }

    return mutated;
}

PreservedAnalyses GadgetEncryptionPass::run(Module& m, ModuleAnalysisManager&)
{
    return RunGadgetEncryption(m) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}