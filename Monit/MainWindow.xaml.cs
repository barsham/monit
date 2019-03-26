using System;
using System.Collections.Generic;
using System.Windows;
using System.Runtime.InteropServices;
using System.Net;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows.Input;

namespace Monit
{
    public partial class MainWindow : Window
    {
        private const int AF_INET = 2;
        private static List<TcpProcessRecord> TcpActiveConnections = null;
        private static List<UdpProcessRecord> UdpActiveConnections = null;
        DispatcherTimer dispatcherTimer = new DispatcherTimer();

        [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

        [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize,
            bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved = 0);

        private static List<string> filters = new List<string>();

        public MainWindow()
        {
            InitializeComponent();
            Data_grid.BringIntoView();
            dispatcherTimer.Tick += new EventHandler(DispatcherTimer_Tick);
            dispatcherTimer.Interval = new TimeSpan(0, 0, 1);
            dispatcherTimer.Start();
        }

        private void DispatcherTimer_Tick(object sender, EventArgs e)
        {
            MB_change(Mode_Combo, e);
        }

        private static List<TcpProcessRecord> GetAllTcpConnections()
        {
            int bufferSize = 0;
            List<TcpProcessRecord> tcpTableRecords = new List<TcpProcessRecord>();

            uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET,
                TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

            IntPtr tcpTableRecordsPtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                result = GetExtendedTcpTable(tcpTableRecordsPtr, ref bufferSize, true,
                    AF_INET, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

                if (result != 0)
                    return new List<TcpProcessRecord>();

                MIB_TCPTABLE_OWNER_PID tcpRecordsTable = (MIB_TCPTABLE_OWNER_PID)
                                        Marshal.PtrToStructure(tcpTableRecordsPtr,
                                        typeof(MIB_TCPTABLE_OWNER_PID));
                IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr +
                                        Marshal.SizeOf(tcpRecordsTable.dwNumEntries));

                for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.
                        PtrToStructure(tableRowPtr, typeof(MIB_TCPROW_OWNER_PID));

                    List<string> chkLocals = new List<string>();
                    List<string> chkRemotes = new List<string>();
                    List<string> chkPortIncs = new List<string>();
                    List<string> chkPortOuts = new List<string>();
                    List<string> chkPrograms = new List<string>();

                    foreach (string filter in filters)
                    {
                        string[] filterResult = filter.Split(' ');
                        if(filterResult[0] == "LR")
                        {
                            chkLocals.Add(filterResult[1]);
                            chkRemotes.Add(filterResult[2]);
                        }
                        if (filterResult[0] == "PO")
                        {
                            chkPortIncs.Add(filterResult[1]);
                            chkPortOuts.Add(filterResult[2]);
                        }
                        if (filterResult[0] == "PR")
                        {
                            chkPrograms.Add(filterResult[1]);
                        }
                    }

                    string local = new IPAddress(tcpRow.localAddr).ToString();
                    string remote = new IPAddress(tcpRow.remoteAddr).ToString();
                    string portInc = tcpRow.localPort.ToString();
                    string portOut = tcpRow.remotePort.ToString();
                    //if (Process.GetProcesses().Any(process => process.Id == tcpRow.owningPid))
                    //{
                    //    string program = Process.GetProcessById(tcpRow.owningPid).ProcessName;
                    //}
                    if (chkLocals.Count > 0)
                    {
                        bool nop = false;
                        foreach (string chkLocal in chkLocals)
                        {
                            foreach (string chkRemote in chkRemotes)
                            {
                                if (local == chkLocal && remote == chkRemote)
                                {
                                    nop = true;
                                    break;
                                }
                            }
                            if (nop)
                            {
                                break;
                            }
                        }
                        if (!nop)
                        {
                            tcpTableRecords.Add(new TcpProcessRecord(
                              new IPAddress(tcpRow.localAddr),
                              new IPAddress(tcpRow.remoteAddr),
                              BitConverter.ToUInt16(new byte[2] {
                          tcpRow.localPort[1],
                          tcpRow.localPort[0] }, 0),
                              BitConverter.ToUInt16(new byte[2] {
                          tcpRow.remotePort[1],
                          tcpRow.remotePort[0] }, 0),
                              tcpRow.owningPid, tcpRow.state));
                        }
                    }
                    else
                    {
                        tcpTableRecords.Add(new TcpProcessRecord(
                          new IPAddress(tcpRow.localAddr),
                          new IPAddress(tcpRow.remoteAddr),
                          BitConverter.ToUInt16(new byte[2] {
                          tcpRow.localPort[1],
                          tcpRow.localPort[0] }, 0),
                          BitConverter.ToUInt16(new byte[2] {
                          tcpRow.remotePort[1],
                          tcpRow.remotePort[0] }, 0),
                          tcpRow.owningPid, tcpRow.state));
                    }
                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                }
            }
            catch (OutOfMemoryException outOfMemoryException)
            {
                MessageBox.Show(outOfMemoryException.Message, "Out Of Memory",
                    MessageBoxButton.OK, MessageBoxImage.Stop);
            }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message, "Exception",
                    MessageBoxButton.OK, MessageBoxImage.Stop);
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTableRecordsPtr);
            }
            return tcpTableRecords != null ? tcpTableRecords.Distinct().ToList<TcpProcessRecord>() : new List<TcpProcessRecord>();
        }

        private static List<UdpProcessRecord> GetAllUdpConnections()
        {
            int bufferSize = 0;
            List<UdpProcessRecord> udpTableRecords = new List<UdpProcessRecord>();

            uint result = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true,
                AF_INET, UdpTableClass.UDP_TABLE_OWNER_PID);

            IntPtr udpTableRecordPtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                result = GetExtendedUdpTable(udpTableRecordPtr, ref bufferSize, true,
                    AF_INET, UdpTableClass.UDP_TABLE_OWNER_PID);

                if (result != 0)
                    return new List<UdpProcessRecord>();

                MIB_UDPTABLE_OWNER_PID udpRecordsTable = (MIB_UDPTABLE_OWNER_PID)
                    Marshal.PtrToStructure(udpTableRecordPtr, typeof(MIB_UDPTABLE_OWNER_PID));
                IntPtr tableRowPtr = (IntPtr)((long)udpTableRecordPtr +
                    Marshal.SizeOf(udpRecordsTable.dwNumEntries));

                for (int i = 0; i < udpRecordsTable.dwNumEntries; i++)
                {
                    MIB_UDPROW_OWNER_PID udpRow = (MIB_UDPROW_OWNER_PID)
                        Marshal.PtrToStructure(tableRowPtr, typeof(MIB_UDPROW_OWNER_PID));
                    udpTableRecords.Add(new UdpProcessRecord(new IPAddress(udpRow.localAddr),
                        BitConverter.ToUInt16(new byte[2] { udpRow.localPort[1],
                            udpRow.localPort[0] }, 0), udpRow.owningPid));
                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(udpRow));
                }
            }
            catch (OutOfMemoryException outOfMemoryException)
            {
                MessageBox.Show(outOfMemoryException.Message, "Out Of Memory",
                    MessageBoxButton.OK, MessageBoxImage.Stop);
            }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message, "Exception",
                    MessageBoxButton.OK, MessageBoxImage.Stop);
            }
            finally
            {
                Marshal.FreeHGlobal(udpTableRecordPtr);
            }
            return udpTableRecords != null ? udpTableRecords.Distinct().ToList<UdpProcessRecord>() : new List<UdpProcessRecord>();
        }

        private void MB_change(object sender, EventArgs e)
        {
            if (Mode_Combo.SelectedIndex == (int)Protocol.TCP)
            {
                if (dispatcherTimer.IsEnabled)
                {
                    TcpActiveConnections = GetAllTcpConnections();
                }
                Data_grid.ItemsSource = TcpActiveConnections;
            }
            else if (Mode_Combo.SelectedIndex == (int)Protocol.UDP)
            {
                if (dispatcherTimer.IsEnabled)
                {
                    UdpActiveConnections = GetAllUdpConnections();
                }
                Data_grid.ItemsSource = UdpActiveConnections;
            }
        }

        private void Start_Capture_Click(object sender, EventArgs e)
        {
            dispatcherTimer.IsEnabled = true;
            Stop_capture.Background = new SolidColorBrush(Colors.LightCyan);
            Start_capture.Background = new SolidColorBrush(Colors.Gray);
            Start_capture.IsEnabled = false;
            Stop_capture.IsEnabled = true;
        }

        private void Stop_Capture_Click(object sender, EventArgs e)
        {
            dispatcherTimer.IsEnabled = false;
            Stop_capture.Background = new SolidColorBrush(Colors.Gray);
            Start_capture.Background = new SolidColorBrush(Colors.LightCyan);
            MB_change(Mode_Combo, e);
            Start_capture.IsEnabled = true;
            Stop_capture.IsEnabled = false;
        }

        private void Txt_local_ip_keycatch(object sender, KeyEventArgs e)
        {
            if(e.Key == Key.Enter)
            {
                if(txt_remote_ip.Text.Length < 1)
                {
                    MessageBox.Show("Please enter a remote host ip adress.", "Input error",MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
                else if (txt_local_ip.Text.Length < 1)
                {
                    MessageBox.Show("Please enter a valid local host ip adress.", "Input error", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
                else
                {
                    filters.Add("LR " + txt_local_ip.Text + " " + txt_remote_ip.Text);
                    txt_filters.Text += txt_local_ip.Text + " >> " + txt_remote_ip.Text + "\n";
                }
            }
        }

        private void Txt_remote_ip_keycatch(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                if (txt_local_ip.Text.Length < 1)
                {
                    MessageBox.Show("Please enter a local host ip adress.", "Input error", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
                else if (txt_remote_ip.Text.Length < 1)
                {
                    MessageBox.Show("Please enter a valid remote host ip adress.", "Input error", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
                else
                {
                    filters.Add("LR " + txt_local_ip.Text + " " + txt_remote_ip.Text);
                    txt_filters.Text += txt_local_ip.Text + " >> " + txt_remote_ip.Text + "\n";
                }
            }
        }

        private void Txt_port_keycatch(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                txt_filters.Text += txt_port.Text + "\n";
            }
        }

        private void Txt_program_keycatch(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                txt_filters.Text += txt_program.Text + "\n";
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public MibTcpState state;
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public uint remoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public int owningPid;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public MIB_TCPROW_OWNER_PID[] table;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public int owningPid;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public UdpProcessRecord[] table;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class UdpProcessRecord
    {
        [DisplayName("Local Address")]
        public IPAddress LocalAddress { get; set; }
        [DisplayName("Local Port")]
        public uint LocalPort { get; set; }
        [DisplayName("Process ID")]
        public int ProcessId { get; set; }
        [DisplayName("Process Name")]
        public string ProcessName { get; set; }

        public UdpProcessRecord(IPAddress localAddress, uint localPort, int pId)
        {
            LocalAddress = localAddress;
            LocalPort = localPort;
            ProcessId = pId;
            if (Process.GetProcesses().Any(process => process.Id == pId))
                ProcessName = Process.GetProcessById(ProcessId).ProcessName;
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    public class TcpProcessRecord
    {
        [DisplayName("Local Address")]
        public IPAddress LocalAddress { get; set; }
        [DisplayName("Local Port")]
        public ushort LocalPort { get; set; }
        [DisplayName("Remote Address")]
        public IPAddress RemoteAddress { get; set; }
        [DisplayName("Remote Port")]
        public ushort RemotePort { get; set; }
        [DisplayName("State")]
        public MibTcpState State { get; set; }
        [DisplayName("Process ID")]
        public int ProcessId { get; set; }
        [DisplayName("Process Name")]
        public string ProcessName { get; set; }

        public TcpProcessRecord(IPAddress localIp, IPAddress remoteIp, ushort localPort,
            ushort remotePort, int pId, MibTcpState state)
        {
            LocalAddress = localIp;
            RemoteAddress = remoteIp;
            LocalPort = localPort;
            RemotePort = remotePort;
            State = state;
            ProcessId = pId;
            if (Process.GetProcesses().Any(process => process.Id == pId))
            {
                ProcessName = Process.GetProcessById(ProcessId).ProcessName;
            }
        }
    }

    public enum Protocol
    {
        TCP,
        UDP
    }
    public enum TcpTableClass
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }
    public enum UdpTableClass
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,
        UDP_TABLE_OWNER_MODULE
    }
    public enum MibTcpState
    {
        CLOSED = 1,
        LISTENING = 2,
        SYN_SENT = 3,
        SYN_RCVD = 4,
        ESTABLISHED = 5,
        FIN_WAIT1 = 6,
        FIN_WAIT2 = 7,
        CLOSE_WAIT = 8,
        CLOSING = 9,
        LAST_ACK = 10,
        TIME_WAIT = 11,
        DELETE_TCB = 12,
        NONE = 0
    }
}
