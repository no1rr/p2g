import idaapi
import idc
import idautils
import ida_search
import ida_nalt
import ida_bytes
import ida_funcs
import ida_kernwin
import sark
import networkx as nx
import ida_graph


class CustomNodeHandler(sark.ui.AddressNodeHandler):
    def on_click(self, value, attrs):
        if sark.ui.NXGraph.BG_COLOR in attrs:
            # red -> white
            attrs[sark.ui.NXGraph.BG_COLOR] = 0x80 if attrs[sark.ui.NXGraph.BG_COLOR] != 0x80 else 0xffffff 
        else:
            attrs[sark.ui.NXGraph.BG_COLOR] = 0x80
        #self.update_node_info()
        return True

class NXGraphEx(sark.ui.NXGraph):
    def update_node_info(self):
        super().update_node_info()
    
    def OnClick(self, node_id):
        super().OnClick(node_id)
        self.update_node_info()
        self.Refresh()
        return True
class FunctionChooser(ida_kernwin.Choose):
    def __init__(self, title, items):
        ida_kernwin.Choose.__init__(self, title, [["Function", 20], ["Address", 10]], flags=ida_kernwin.Choose.CH_MODAL)
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnClose(self):
        pass

class P2GPlugin(idaapi.plugin_t):

    MAX_SEARCH_DEPTH = 20
    flags = idaapi.PLUGIN_UNL
    comment = "p2g plugin"
    help = "p2g plugin"
    wanted_name = "p2g plugin"
    #wanted_hotkey = "Ctrl-Shift-J"
    
    def findXRefs(self, start: sark.Function, end: sark.Function, path, max_depth, include_data_xref):

        if max_depth == 0:
            return False
        max_depth -= 1

        path = path + [start]

        if start.start_ea == end.start_ea:
            return [path]
        
        # 如果当前节点在路径中，避免循环
        if start in path[:-1]:  
            return []
        paths = []

        if include_data_xref:
            refs = list(start.xrefs_from)
        else:
            refs = list(start.calls_from)

        for node in refs:  
            # 递归查找路径
            newpaths = self.findXRefs(sark.Function(ea=node.to), end, path, max_depth, include_data_xref)
            for newpath in newpaths:
                paths.append(newpath)
        
        return paths
        
    def show_function_chooser(self, title="Select Function"):
        # 收集所有函数名
        functions = []
        for func_ea in idautils.Functions():
            func_name = ida_funcs.get_func_name(func_ea)
            functions.append([func_name, f"0x{func_ea:X}"])

        # 创建并显示选择器
        chooser = FunctionChooser(title, functions)
        selected = chooser.Show(modal=True)
        
        if selected != -1:  # 如果用户选择了某个函数
            selected_function, selected_address = functions[selected]
            print(f"Selected function: {selected_function}, Address: {selected_address}")
            return selected_address
        else:
            print("No function selected")
    def func2(self):
        print("abababa")

    def main(self):

        source_func = sark.Function(ea=int(self.show_function_chooser("source function"),16))
        sink_func = int(self.show_function_chooser("sink function"), 16)

        # 获取目标函数的函数对象
        try:
            s = sark.Segment(ea=sink_func)
            if s.name == "UNDEF":
                sink_func = sark.ExternFunction(ea=sink_func)
            else:
                sink_func = sark.Function(ea=sink_func)  # type: ignore
        except Exception as e:
            # 如果目标函数不存在，则提示错误
            # traceback.print_exc()
            print("Error: target function does not exist!")
            return
          
        # 创建有向图
        G = nx.DiGraph()
 
        # 在这里实现查找两个函数之间交叉引用关系的代码...
        print(f"searching a path between func {source_func.demangled} and {sink_func.demangled}, max search depth is {self.MAX_SEARCH_DEPTH}")

        btn_selected = idaapi.ask_yn(idaapi.ASKBTN_NO, "是否包括 data xrefs?")
        if btn_selected == idaapi.ASKBTN_CANCEL:
            return

        paths = self.findXRefs(source_func, sink_func, [], self.MAX_SEARCH_DEPTH, include_data_xref=True if btn_selected == idaapi.ASKBTN_YES else False)
        
        # 添加边
        for path in paths:
            print(path)
            for j in range(len(path)-1):
                G.add_edge(path[j].ea, path[j+1].ea)
 
        if len(G.nodes()) > 0:
            # draw graph
            G.nodes[source_func.ea][sark.ui.NXGraph.BG_COLOR] = 0x80 
            G.nodes[sink_func.ea][sark.ui.NXGraph.BG_COLOR] = 0x8000
 
            title = f"{source_func.demangled} -> {sink_func.demangled}"
 
            # Create an NXGraph viewer
            #viewer = sark.ui.NXGraph(G, handler=CustomNodeHandler(), title=title)
            viewer = NXGraphEx(G, handler=CustomNodeHandler(), title=title)
            #viewer = CustomGraph("aaa", paths)
 
            # Show the graph
            viewer.Show()
        else:
            idaapi.warning("Cannot find any path!")

    def __init__(self):
        super().__init__()
    
    def init(self):
        print(self.wanted_name + " init")
        return idaapi.PLUGIN_OK

    def run(self, args):
        self.main()
        
    def term(self):
        print(self.wanted_name + " exit")

def PLUGIN_ENTRY():
    return P2GPlugin()
