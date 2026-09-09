const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

initializeApp();

const auth = getAuth();
const db = getFirestore();

exports.createStaff = onCall(async (request) => {
  if (!request.auth) {
    throw new HttpsError(
      "unauthenticated",
      "You must be signed in."
    );
  }

  const adminUid = request.auth.uid;

  const adminSnap = await db
    .collection("staff")
    .doc(adminUid)
    .get();

  if (!adminSnap.exists) {
    throw new HttpsError(
      "permission-denied",
      "Admin profile not found."
    );
  }

  const adminData = adminSnap.data();

  if (
    adminData.status !== "Active" ||
    adminData.role !== "Super Admin"
  ) {
    throw new HttpsError(
      "permission-denied",
      "Only Super Admin can create staff accounts."
    );
  }

  const {
    name,
    email,
    password,
    role,
    permissions
  } = request.data || {};

  if (!name || !email || !password || !role) {
    throw new HttpsError(
      "invalid-argument",
      "Name, email, password and role are required."
    );
  }

  if (String(password).length < 8) {
    throw new HttpsError(
      "invalid-argument",
      "Password must be at least 8 characters."
    );
  }

  const allowedRoles = [
    "Order Manager",
    "Product Manager",
    "Inventory Manager",
    "Accountant / Finance",
    "Customer Support",
    "Delivery Manager",
    "Marketing Manager"
  ];

  if (!allowedRoles.includes(role)) {
    throw new HttpsError(
      "invalid-argument",
      "Invalid staff role."
    );
  }

  let userRecord;

  try {
    userRecord = await auth.createUser({
      email: String(email).trim().toLowerCase(),
      password: String(password),
      displayName: String(name).trim(),
      disabled: false
    });
  } catch (error) {
    if (error.code === "auth/email-already-exists") {
      throw new HttpsError(
        "already-exists",
        "This email is already registered."
      );
    }

    throw new HttpsError(
      "internal",
      "Unable to create authentication account."
    );
  }

  const safePermissions =
    permissions && typeof permissions === "object"
      ? permissions
      : {};

  try {
    await db
      .collection("staff")
      .doc(userRecord.uid)
      .set({
        name: String(name).trim(),
        email: String(email).trim().toLowerCase(),
        role,
        status: "Active",
        permissions: safePermissions,
        authUid: userRecord.uid,
        createdBy: adminUid,
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp()
      });

    await db.collection("audit_logs").add({
      action: "STAFF_CREATED",
      targetUid: userRecord.uid,
      targetEmail: String(email).trim().toLowerCase(),
      targetRole: role,
      performedBy: adminUid,
      createdAt: FieldValue.serverTimestamp()
    });

    return {
      success: true,
      uid: userRecord.uid,
      message: "Staff account created successfully."
    };

  } catch (error) {
    // Roll back Authentication account if Firestore creation fails.
    try {
      await auth.deleteUser(userRecord.uid);
    } catch (rollbackError) {
      console.error("Rollback failed:", rollbackError);
    }

    console.error(error);

    throw new HttpsError(
      "internal",
      "Staff profile could not be created."
    );
  }
});
