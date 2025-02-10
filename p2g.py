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
        return True

class NXGraphEx(sark.ui.NXGraph):
    def update_node_info(self):
        super().update_node_info()
    
    def OnClick(self, node_id):
        super().OnClick(node_id)
        self.update_node_info()
        self.Refresh()
        return True

class function_chooser_t(ida_kernwin.Choose):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, nb=5, flags=ida_kernwin.Choose.CH_MULTI):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Function", 20],
                ["Address", 10]
            ],
            flags=flags,
            embedded=True,
            width=30,
            height=6)

        self.items = [[ida_funcs.get_func_name(func_ea), f"0x{func_ea:X}"] for func_ea in idautils.Functions()]
        self.icon = 5
        # 保存每次选择的项
        self.sel_items = []

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, items):
        selected_items = [self.items[i] for i in items]
        print("Selected:", selected_items)
        self.sel_items += [int(self.items[i][1], 16) for i in items]
        return items
        
class FunctionSelectionForm(ida_kernwin.Form):

    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(self, r"""STARTITEM 123
BUTTON YES* Run
BUTTON CANCEL Cancel
p2g

<##data ref?## No:{rNo}> <Yes:{rYes}>{iDataXref}> 
<##max depth## max depth:{iDepth}>                                                         
<sink:{sourceFunction}> | <source:{sinkFunction}> | <exclude:{excludeFunction}>
""",
        { 
          'iDataXref': F.RadGroupControl(("rYes", "rNo")),
          'iDepth': F.NumericInput(F.FT_DEC, 20),
          'sourceFunction': F.EmbeddedChooserControl(function_chooser_t("sourceFunction")),
          'sinkFunction': F.EmbeddedChooserControl(function_chooser_t("sinkFunction")), 
          'excludeFunction': F.EmbeddedChooserControl(function_chooser_t("excludeFunction"))
        })   

    def get_user_data(self):
        return [self.sourceFunction.value.sel_items, 
                self.sinkFunction.value.sel_items, 
                self.excludeFunction.value.sel_items, 
                False if self.iDataXref.value==0 else True, 
                self.iDepth.value]

class P2GPlugin(idaapi.plugin_t):

    MAX_SEARCH_DEPTH = 20
    flags = idaapi.PLUGIN_UNL
    comment = "p2g plugin"
    help = "p2g plugin"
    wanted_name = "p2g plugin"
    #wanted_hotkey = "Ctrl-Shift-J"

    reach_max_depth = False
    
    def findXRefs(self, start, end, path, max_depth, exclude_funcs, include_data_xref):

        if max_depth == 0:
            self.reach_max_depth = True
            print(f"max depth reached: {start}")
            return []
        max_depth -= 1

        if start.start_ea in exclude_funcs:
            print(f"exclude func reached: {start}")
            return []

        # aviod loop
        if start in path:  
            return []

        path = path + [start]

        if start.start_ea == end.start_ea:
            return [path]
        
        paths = []
        refs = list(start.xrefs_from) if include_data_xref else list(start.calls_from)

        if len(refs) == 0:
            return []
        for node in refs:  
            # 递归查找路径
            newpaths = self.findXRefs(sark.Function(ea=node.to), end, path, max_depth, exclude_funcs, include_data_xref)
            for newpath in newpaths:
                paths.append(newpath)
        
        return paths

    def main(self):

        form = FunctionSelectionForm()
        form.Compile()
        form.Execute()
        
        source_func, sink_func, exclude_funcs, idata_xref, max_depth = form.get_user_data()
        source_func = sark.Function(source_func[0])
        sink_func = sark.Function(sink_func[0])
          
        # 创建有向图
        G = nx.DiGraph()
 
        # 在这里实现查找两个函数之间交叉引用关系的代码...
        print(f"searching a path between func {source_func.demangled} and {sink_func.demangled}, max search depth is {self.MAX_SEARCH_DEPTH}")

        paths = self.findXRefs(source_func, sink_func, [], max_depth, exclude_funcs, idata_xref)
        
        # 添加边
        cnt = 0
        for path in paths:
            print(f"{cnt}: {path}")
            cnt += 1
            for j in range(len(path)-1):
                G.add_edge(path[j].ea, path[j+1].ea)
 
        if len(G.nodes()) > 0:
            # draw graph
            G.nodes[source_func.ea][sark.ui.NXGraph.BG_COLOR] = 0x80 
            G.nodes[sink_func.ea][sark.ui.NXGraph.BG_COLOR] = 0x8000
 
            title = f"{source_func.demangled} -> {sink_func.demangled}"
 
            # Create an NXGraph viewer
            viewer = NXGraphEx(G, handler=CustomNodeHandler(), title=title)
 
            # Show the graph
            viewer.Show()
            if self.reach_max_depth:
                idaapi.warning("max depth reached, check output")

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
