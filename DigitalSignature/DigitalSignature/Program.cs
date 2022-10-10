using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Security.Cryptography;
using System.Text;

Console.WriteLine("Hello, World!");
Console.WriteLine(Pkcs11Library.GetLog());

public sealed class Pkcs11Library
{
    private static readonly Pkcs11InteropFactories Factories = new();
    private static readonly string Pkcs11LibraryPath = @"D:\SoftHSM2\lib\softhsm2-x64.dll";

    private static IObjectHandle? FindFirstObject(ISession session, List<IObjectAttribute> objectAttributes)
    {
        session.FindObjectsInit(objectAttributes);

        var foundObjects = session.FindObjects(1);

        session.FindObjectsFinal();

        return foundObjects.FirstOrDefault();
    }

    public static IObjectHandle? GetPublicKey(ISession session) =>
        FindFirstObject(session, new() { session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY) });

    public static IObjectHandle? GetPrivateKey(ISession session) =>
        FindFirstObject(session, new() { session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY) });

    public static ISlot? GetSignableSlot(
        IPkcs11Library pkcs11Library,
        ulong slotId,
        string tokenSerialNumber) =>
        pkcs11Library.GetSlotList(SlotsType.WithTokenPresent)
                     .FirstOrDefault(s =>
                            s.GetTokenInfo()
                             .SerialNumber
                             .Equals(tokenSerialNumber, StringComparison.InvariantCulture)
                         && s.SlotId
                             .Equals(slotId)
                         && s.GetMechanismList()
                             .Any(m => s.GetMechanismInfo(m).MechanismFlags.Sign));

    public static byte[] Sign(
        byte[] data,
        string userPin,
        uint slotId,
        string tokenSerialNumber)
    {
        using IPkcs11Library library =
            Factories.Pkcs11LibraryFactory
                     .LoadPkcs11Library(
                         Factories,
                         Pkcs11LibraryPath,
                         AppType.MultiThreaded);

        var slot = GetSignableSlot(library, slotId, tokenSerialNumber)
                       ?? throw new ArgumentException(
                            $"Slot with Id `{slotId}` and Token with SerialNumber `{tokenSerialNumber}` not found");

        using var session = slot.OpenSession(SessionType.ReadOnly);

        session.Login(CKU.CKU_USER, userPin);

        var mechanismParams = session.Factories
                                     .MechanismParamsFactory
                                     .CreateCkRsaPkcsPssParams(
                                         (ulong)CKM.CKM_SHA256,
                                         (ulong)CKG.CKG_MGF1_SHA256,
                                         GetHashLength(data));

        using IMechanism mechanism =
            session.Factories
                   .MechanismFactory
                   .Create(CKM.CKM_SHA256_RSA_PKCS_PSS, mechanismParams);

        var privateKey = GetPrivateKey(session)
                             ?? throw new ArgumentException("Private key not found");

        byte[] signature = session.Sign(mechanism, privateKey, data);

        session.Logout();

        return signature;
    }

    private static ulong GetHashLength(byte[] data) =>
        (ulong)SHA256.Create()
                     .ComputeHash(data)
                     .Length;

    public static string GetLog()
    {
        using var library =
            Factories.Pkcs11LibraryFactory
                     .LoadPkcs11Library(
                         Factories,
                         Pkcs11LibraryPath,
                         AppType.MultiThreaded);

        var libraryInfo = library.GetInfo();

        var builder = new StringBuilder()
            .Append("Library: \n")
            .Append($"  Manufacturer:       {libraryInfo.ManufacturerId}\n")
            .Append($"  Description:        {libraryInfo.LibraryDescription}\n")
            .Append($"  Version:            {libraryInfo.LibraryVersion}\n");

        return builder.Append(library
            .GetSlotList(SlotsType.WithOrWithoutTokenPresent)
            .Aggregate(builder, (b, s) =>
            {
                var slotInfo = s.GetSlotInfo();

                builder.Append("Slot:\n")
                       .Append($"  Manufacturer:       {slotInfo.ManufacturerId}\n")
                       .Append($"  SlotId:             {slotInfo.SlotId}\n")
                       .Append($"  Description:        {slotInfo.SlotDescription}\n")
                       .Append($"  Token present:      {slotInfo.SlotFlags.TokenPresent}\n");

                if (slotInfo.SlotFlags.TokenPresent)
                {
                    var tokenInfo = s.GetTokenInfo();

                    builder.Append("Token:\n")
                           .Append($"  Manufacturer:       {tokenInfo.ManufacturerId}\n")
                           .Append($"  Serial number:      {tokenInfo.SerialNumber}\n")
                           .Append($"  Model:              {tokenInfo.Model}\n")
                           .Append($"  Label:              {tokenInfo.Label}\n")
                           .Append("Supported mechanisms: \n")
                           .Append(
                                string.Join(
                                    string.Empty,
                                    s.GetMechanismList()
                                     .Select(m => $"  {m}\n")));
                }

                return builder;
            })).ToString();
    }
}