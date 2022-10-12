using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Security.Cryptography;
using System.Text;

Console.WriteLine("Hello, World!");
Console.WriteLine(Pkcs11Library.GetMachineLog());

public sealed class Pkcs11Library
{
    private static readonly Pkcs11InteropFactories Factories = new();
    private static readonly string Pkcs11LibraryPath = @"D:\SoftHSM2\lib\softhsm2-x64.dll";

    public static void GenerateKeyPair(
        ISession session,
        out IObjectHandle publicKeyHandle,
        out IObjectHandle privateKeyHandle)
    {
        var ckaId = session.GenerateRandom(10); // Key identifier for public/private key pair

        var attributeFactory = session.Factories.ObjectAttributeFactory;

        var publicKeyAttributes = new List<IObjectAttribute>()
        {
            attributeFactory.Create(CKA.CKA_TOKEN, true),
            attributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            attributeFactory.Create(CKA.CKA_PRIVATE, false),
            attributeFactory.Create(CKA.CKA_LABEL, "Public-Key-DigitalSignature"),
            attributeFactory.Create(CKA.CKA_ID, ckaId),
            attributeFactory.Create(CKA.CKA_ENCRYPT, true),
            attributeFactory.Create(CKA.CKA_VERIFY, true),
            attributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true),
            attributeFactory.Create(CKA.CKA_WRAP, true),
            attributeFactory.Create(CKA.CKA_MODULUS_BITS, 1024),
            attributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 })
        };

        var privateKeyAttributes = new List<IObjectAttribute>()
        {
            attributeFactory.Create(CKA.CKA_TOKEN, true),
            attributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            attributeFactory.Create(CKA.CKA_PRIVATE, true),
            attributeFactory.Create(CKA.CKA_LABEL, "Private-Key-DigitalSignature"),
            attributeFactory.Create(CKA.CKA_ID, ckaId),
            attributeFactory.Create(CKA.CKA_SENSITIVE, true),
            attributeFactory.Create(CKA.CKA_DECRYPT, true),
            attributeFactory.Create(CKA.CKA_SIGN, true),
            attributeFactory.Create(CKA.CKA_SIGN_RECOVER, true),
            attributeFactory.Create(CKA.CKA_UNWRAP, true)
        };

        var mechanism = session.Factories
                               .MechanismFactory
                               .Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        session.GenerateKeyPair(
            mechanism,
            publicKeyAttributes,
            privateKeyAttributes,
            out publicKeyHandle,
            out privateKeyHandle);
    }

    public static void DestroyPublicPrivateKeyPair(ISession session)
    {
        session.DestroyObject(GetPublicKey(session));
        session.DestroyObject(GetPrivateKey(session));
    }

    public static IObjectHandle? GetPublicKey(ISession session) =>
        FindFirstObject(session, new() { session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY) });

    public static IObjectHandle? GetPrivateKey(ISession session) =>
        FindFirstObject(session, new() { session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY) });

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

        static ulong GetHashLength(byte[] data) =>
            (ulong)SHA256.Create()
                         .ComputeHash(data)
                         .Length;
    }

    public static string GetMachineLog()
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

    private static IObjectHandle? FindFirstObject(
        ISession session,
        List<IObjectAttribute> objectAttributes)
    {
        session.FindObjectsInit(objectAttributes);

        var foundObjects = session.FindObjects(1);

        session.FindObjectsFinal();

        return foundObjects.FirstOrDefault();
    }

    private static ISlot? GetSignableSlot(
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
}