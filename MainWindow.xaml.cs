using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Security.Cryptography;

namespace BatteryMonitor
{
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        public const ushort BM2_Service_UUID = 65520;
        public const ushort BM2_Characteristic_UUID = 65524;

        public InTheHand.Bluetooth.BluetoothDevice? BatteryMonitorDevice { get; set; }

        public double VoltageD { get; set; }

        private string readoutVoltageS;
        public string VoltageS
        {
            get { return readoutVoltageS; }
            set
            {
                readoutVoltageS = value;
                OnPropertyChanged();
            }
        }

        public MainWindow()
        {
            InitializeComponent();
            //Current = this;
            this.DataContext = this;
            VoltageS = "Finding Monitor";
            ScanForBluetoothClients("Battery Monitor");
        }

        private async void ScanForBluetoothClients(string name)
        {
            this.StatusBox.Background = System.Windows.Media.Brushes.Pink;
            InTheHand.Bluetooth.RequestDeviceOptions? requestDeviceOptions = new InTheHand.Bluetooth.RequestDeviceOptions { AcceptAllDevices = true };
            //var devices = await InTheHand.Bluetooth.Bluetooth.ScanForDevicesAsync(requestDeviceOptions);
            var devices = await InTheHand.Bluetooth.Bluetooth.GetPairedDevicesAsync();

            foreach (InTheHand.Bluetooth.BluetoothDevice device in devices)
            {
                if (device.Name.Contains(name))
                {
                    BatteryMonitorDevice = device;
                }
            }
            this.StatusBox.Background = System.Windows.Media.Brushes.LightGreen;
            AskBattery(BatteryMonitorDevice);
        }

        private async void AskBattery(InTheHand.Bluetooth.BluetoothDevice device)
        {
            var gatt = device.Gatt;
            await gatt.ConnectAsync();
            bool btConnect = gatt.IsConnected;

            //var services = await gatt.GetPrimaryServicesAsync();

            var service = await gatt.GetPrimaryServiceAsync(BM2_Service_UUID);

            if (service != null)
            {
                GattCharacteristic characteristic = await service.GetCharacteristicAsync(BM2_Characteristic_UUID);

                if (characteristic != null)
                {
                    // initialize status
                    GattCommunicationStatus status = GattCommunicationStatus.Unreachable;
                    var cccdValue = GattClientCharacteristicConfigurationDescriptorValue.None;
                    if (characteristic.CharacteristicProperties.HasFlag(GattCharacteristicProperties.Indicate))
                    {
                        cccdValue = GattClientCharacteristicConfigurationDescriptorValue.Indicate;
                    }

                    else if (characteristic.CharacteristicProperties.HasFlag(GattCharacteristicProperties.Notify))
                    {
                        cccdValue = GattClientCharacteristicConfigurationDescriptorValue.Notify;
                    }

                    // BT_Code: Must write the CCCD in order for server to send indications.
                    // We receive them in the ValueChanged event handler.
                    status = await characteristic.WriteClientCharacteristicConfigurationDescriptorAsync(cccdValue);
                    characteristic.ValueChanged += CharacteristicValueChanged;
                }
            }
        }

        public void CharacteristicValueChanged(Windows.Devices.Bluetooth.GenericAttributeProfile.GattCharacteristic gattChar,
                                             Windows.Devices.Bluetooth.GenericAttributeProfile.GattValueChangedEventArgs args)
        {
            // BT_Code: An Indicate or Notify reported that the value has changed.
            // Display the new value with a timestamp.
            CryptoLE crp = new CryptoLE();
            byte[] encryptedData;
            CryptographicBuffer.CopyToByteArray(args.CharacteristicValue, out encryptedData);
            var decryptData = crp.BM2_Decrypt(encryptedData);
            string sData = BitConverter.ToString(decryptData).Replace("-", string.Empty);
            string packetS = sData.Substring(0, 2);
            string voltageS = "0x0" + sData.Substring(2, 3);
            int voltageI = Convert.ToInt16(voltageS, 16);
            double voltageLast = VoltageD;
            VoltageD = ((double)voltageI) / 100.0;
            if (VoltageD != voltageLast)
            {
                VoltageS = VoltageD.ToString() + " Volts";
            }
        }

        // Declare the property changed event
        public event PropertyChangedEventHandler PropertyChanged;

        // Create the OnPropertyChanged method to raise the event
        // The calling member's name will be used as the parameter.
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

    }
}


