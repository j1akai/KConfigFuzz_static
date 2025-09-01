#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include "llvm/IR/Instruction.h"
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
#include <llvm/IR/LegacyPassManager.h>
#include <map>
#include <vector>
#include "llvm/IR/CFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/IRBuilder.h"

#include "Constraint.h"
#include "Config.h"
#include "Common.h"

bool ConstraintPass::doInitialization(Module *M)
{
  return false;
}

void splitStringSmart(const string& str, vector<string>& result, char delim) {
  result.clear();
  int paren = 0, brace = 0, bracket = 0;
  int start = 0;
  for (int i = 0; i < (int)str.length(); i++) {
      char c = str[i];
      if (c == '(') paren++;
      else if (c == ')') paren--;
      else if (c == '{') brace++;
      else if (c == '}') brace--;
      else if (c == '[') bracket++;
      else if (c == ']') bracket--;

      if (c == delim && paren == 0 && brace == 0 && bracket == 0) {
          string arg = str.substr(start, i - start);
          strip(arg);
          result.push_back(arg);
          start = i + 1;
      }
  }
  string last = str.substr(start);
  strip(last);
  if (!last.empty()) result.push_back(last);
}

string extractConstNameFromArg(const string& expr, int idx) {
  size_t pos = expr.find('(');
  size_t end = expr.find(')');
  if (pos == string::npos || end == string::npos) return "";

  string argStr = expr.substr(pos + 1, end - pos - 1);
  vector<string> args;
  splitStringSmart(argStr, args, ',');
  if (idx < 0 || idx >= (int)args.size()) return "";

  string arg = args[idx];
  strip(arg);

  // 去掉类型转换 (int)、(unsigned long) 等
  while (arg[0] == '(') {
      size_t close = arg.find(')');
      if (close == string::npos) break;
      arg = arg.substr(close + 1);
      strip(arg);
  }

  // 去掉前缀解引用 *& 等
  while (arg.size() > 1 && (arg[0] == '&' || arg[0] == '*')) {
      arg = arg.substr(1);
      strip(arg);
  }

  // 如果是宏或标识符，直接返回
  if (isAlpha(arg[0]) || arg[0] == '_') {
      // 提取第一个连续的标识符
      string name = "";
      for (char c : arg) {
          if (isAlnum(c) || c == '_') name += c;
          else break;
      }
      return name;
  }

  // 如果是 (FOO) 形式，尝试提取 FOO
  if (arg[0] == '(' && arg.back() == ')') {
      string inner = arg.substr(1, arg.size() - 2);
      strip(inner);
      return extractConstNameFromArg("call(" + inner + ")", 0);
  }

  return "";
}

bool parseAndCheckArgCount(const string& expr, int expectedArgCount, int targetArgIdx, int& foundLine, int currentLine) {
  size_t pos = expr.find('(');
  if (pos == string::npos) return false;
  pos++;

  size_t end = expr.find(')');
  if (end == string::npos || end <= pos) return false;

  string argStr = expr.substr(pos, end - pos);
  strip(argStr);
  if (argStr.empty()) return expectedArgCount == 0;

  vector<string> args;
  splitStringSmart(argStr, args, ','); // 需要跳过嵌套括号内的逗号
  return (int)args.size() == expectedArgCount;
}

string getCosntName(string srcFileName, CallInst *CI, int constArgIdx)
{
  if (!CI || constArgIdx < 0)
    return "";

  DILocation *Loc = CI->getDebugLoc();
  if (!Loc)
    return "";
  int startLine = Loc->getLine();
  if (startLine <= 0 || srcFileName.empty())
    return "";

  int totalArgs = CI->arg_size();
  if (constArgIdx >= totalArgs)
    return "";

  ifstream file(srcFileName);
  if (!file.is_open())
  {
    DEBUG("Failed to open source file: " << srcFileName << "\n");
    return "";
  }

  vector<string> lines;
  string line;
  while (getline(file, line))
  {
    lines.push_back(line);
  }
  file.close();

  if (lines.empty() || startLine > (int)lines.size())
  {
    return "";
  }

  // 转换为 0-indexed
  int startIdx = startLine - 1;

  // 用于收集多行调用的缓冲区
  string buffer = "";
  int parenCount = 0;
  int foundLine = -1;

  // 双向搜索：先向下，再向上（因为调用通常在 debug loc 附近，且常在下方展开）
  for (int direction = 0; direction < 2; direction++)
  {
    if (direction == 0)
    {
      // 向下搜索
      for (int i = startIdx; i < (int)lines.size(); i++)
      {
        string l = lines[i];
        strip(l);
        if (l.empty() || l[0] == '#' ||
            startsWith(l, "//") ||
            l.find("/*") != string::npos)
        {
          continue;
        }

        buffer += " " + l;
        parenCount += count(l.begin(), l.end(), '(');
        parenCount -= count(l.begin(), l.end(), ')');

        if (parenCount > 0 && buffer.find('(') != string::npos)
        {
          // 可能是多行调用，继续收集
          continue;
        }
        else if (parenCount == 0 && buffer.find('(') != string::npos)
        {
          // 完整括号，尝试解析
          if (parseAndCheckArgCount(buffer, totalArgs, constArgIdx, foundLine, i))
          {
            return extractConstNameFromArg(buffer, constArgIdx);
          }
          else
          {
            buffer = ""; // 重置，继续找
          }
        }
        else
        {
          buffer = ""; // 非法，重置
        }
      }
    }
    else
    {
      // 向上搜索
      buffer = "";
      parenCount = 0;
      for (int i = startIdx; i >= 0; i--)
      {
        string l = lines[i];
        strip(l);
        if (l.empty() || l[0] == '#' ||
            startsWith(l, "//") ||
            l.find("/*") != string::npos)
        {
          continue;
        }

        // 向上搜索时，插入到前面
        if (buffer.empty())
        {
          buffer = l;
        }
        else
        {
          buffer = l + " " + buffer;
        }
        parenCount += count(l.begin(), l.end(), '(');
        parenCount -= count(l.begin(), l.end(), ')');

        if (parenCount > 0 && buffer.find(')') != string::npos)
        {
          // 在向上找时，如果已经有 ')' 但还有 '(' 没配对，继续
          continue;
        }
        else if (parenCount == 0 && buffer.find('(') != string::npos && buffer.find(')') != string::npos)
        {
          if (parseAndCheckArgCount(buffer, totalArgs, constArgIdx, foundLine, i))
          {
            return extractConstNameFromArg(buffer, constArgIdx);
          }
          else
          {
            buffer = ""; // 重置
          }
        }
      }
    }
    // 每次换方向前重置
    buffer = "";
    parenCount = 0;
  }

  return "";
}

// string getCosntName(string srcFileName, CallInst *CI, int constArgIdx) {
// 	string constName = "";
// 	if (DILocation *Loc = CI->getDebugLoc()) {
// 		int lineNum = Loc->getLine();
// 		if (srcFileName != "" && lineNum != 0) {
// 			int argNum = CI->arg_size();
// 			int currentArgNum = 0;
//       cout << "FileName: " << srcFileName << " lineNum: " << lineNum << " argNum: " << argNum << "\n";
// 			ifstream file(srcFileName);
// 			while (currentArgNum < argNum) {
// 				gotoLine(file, lineNum);
// 				string line;
// 				getline(file, line);
// 				strip(line);

//         // 由于配置项宏等的存在，会导致行号不准确，因此向下多读几行
//         if (line.empty() || line[0] == '#' || startsWith(line, "//") || line.find("/*") != string::npos) {
//           lineNum++;
//           continue;
//         }

// 				if (line.size() == 0)
// 					break;
// 				vector<string> splitRes;
// 				splitString(line, splitRes, ",");
// 				currentArgNum += splitRes.size();
// 				if (constArgIdx < currentArgNum) {
// 					if (constArgIdx == 0) {
// 						string tmp = splitRes[constArgIdx];
// 						vector<string> tmpSplitRes;
// 						splitString(tmp, tmpSplitRes, "(");
// 						constName = tmpSplitRes[1];
// 						strip(constName);
// 					} else if (constArgIdx == argNum-1) {
// 						string tmp = splitRes[constArgIdx];
// 						vector<string> tmpSplitRes;
// 						splitString(tmp, tmpSplitRes, ")");
// 						constName = tmpSplitRes[0];
// 						strip(constName);
// 					} else {
// 						constName = splitRes[constArgIdx];
// 						strip(constName);
// 					}
// 					break;
// 				}
// 			}
// 			file.close();
// 		}
// 	}
// 	return constName;
// }

bool ConstraintPass::doModulePass(Module *M)
{
  for (auto gv = M->global_begin(); gv != M->global_end(); gv++)
  {
    GlobalVariable *g = dyn_cast<GlobalVariable>(&*gv);
    if (g == nullptr)
    {
      continue;
    }
    if (!g->hasInitializer())
    {
      continue;
    }
    if (g->getValueType()->isStructTy())
    {

      if (!g->isConstant() && (!g->hasSection() || !g->getSection().contains("read_mostly")))
        continue;

      Constant *constGlobal = g->getInitializer();
      if (constGlobal != nullptr)
      {
        auto constStruct = dyn_cast<ConstantStruct>(constGlobal);
        if (constStruct != nullptr)
        {
          string res = "";
          for (int i = 0; i < constStruct->getNumOperands(); i++)
          {
            auto val = constStruct->getAggregateElement(i);
            const ConstantDataArray *currDArray = dyn_cast<ConstantDataArray>(val);
            raw_string_ostream ss(res);
            if (currDArray != nullptr)
            {
              if (res == "")
              {
                raw_string_ostream ss(res);
                if (currDArray != nullptr && currDArray->isString())
                {
                  ss << currDArray->getAsString();
                  res = ss.str().c_str();
                  OP << res << "\n";
                  for (int i = 0; i < strlen(res.c_str()); i++)
                  {
                    if (!isAlnum(res[i]))
                    {
                      res = "";
                      break;
                    }
                  }
                }
              }
              else
              {
                // TODO: more than one string in one struct
                res = "";
                break;
              }
            }
          }
          if (res == "")
            continue;

          for (int i = 0; i < constStruct->getNumOperands(); i++)
          {
            auto constStruct = dyn_cast<ConstantStruct>(constGlobal);
            if (constStruct != nullptr)
            {
              auto val = constStruct->getAggregateElement(i);

              if (Function *F = dyn_cast<Function>(val))
              {

                GlobalCtx.Func2ConstFromFopsMap[F->getName().str()] = res;
              }
            }
          }
        }
      }
    }
  }

  for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++)
  {
    Function *F = &*mi;
    if (F->hasName())
    {
      string funcName = F->getName().str();

      if (GlobalCtx.RegisterFunctionMap.count(funcName) != 0)
      {
        for (auto posPair : GlobalCtx.RegisterFunctionMap[funcName])
        {

          int constPos = posPair.first;
          int functionPointerPos = posPair.second;
          for (User *user : F->users())
          {
            if (CallInst *callInst = dyn_cast<CallInst>(user))
            {
              Value *constOp = callInst->getArgOperand(constPos);
              Value *functionPointerOp = callInst->getArgOperand(functionPointerPos);
              if (constOp && functionPointerOp)
              {
                ConstantInt *constInt = dyn_cast<ConstantInt>(constOp);
                Function *functionPointer = dyn_cast<Function>(functionPointerOp);
                if (constInt == nullptr || functionPointer == nullptr)
                {
                  continue;
                }
                string functionPointerName = functionPointer->getName().str();
                if (functionPointerName == "")
                {
                  continue;
                }
                uint64_t constIntVal = constInt->getZExtValue();
                Function *targetF = callInst->getFunction();
                string srcFileName = targetF->getParent()->getSourceFileName();

                string constName = getCosntName(srcFileName, callInst, constPos);
                errs() << "dc1: " << constIntVal << " " << functionPointer->getName() << " " << constName << "\n";
                if (constName == "")
                  continue;
                GlobalCtx.HandlerConstraint[functionPointerName].insert(make_pair(constIntVal, constName));
              }
            }
          }
        }
      }
      if (funcName == "bt_sock_register")
      {
        for (User *user : F->users())
        {
          if (CallInst *callInst = dyn_cast<CallInst>(user))
          {
            auto theProto = dyn_cast<Constant>(callInst->getOperand(0));
            auto theOps = dyn_cast<GlobalVariable>(callInst->getOperand(1));
            OP << "callsite of bt_sock_register: " << *callInst << "\n";
            OP << "extracted proto: " << *theProto << "|" << "theOps: " << *theOps << "\n";
            if (theOps->hasInitializer())
            {
              auto constStruct = dyn_cast<ConstantStruct>(theOps->getInitializer());
              Constant *createPtr = constStruct->getOperand(1);
              if (createPtr->isNullValue())
                continue;
              Function *funcPtr = dyn_cast<Function>(createPtr);
              string functionPointerName = funcPtr->getName().str();
              ConstantInt *constInt = dyn_cast<ConstantInt>(theProto);
              uint64_t constIntVal = constInt->getZExtValue();
              Function *targetF = callInst->getFunction();
              string srcFileName = targetF->getParent()->getSourceFileName();
              string constName = getCosntName(srcFileName, callInst, 0);
              GlobalCtx.HandlerConstraint[functionPointerName].insert(make_pair(constIntVal, constName));
            }
          }
        }
      }
    }
  }
  return false;
}

bool ConstraintPass::doFinalization(Module *M)
{
  return false;
}