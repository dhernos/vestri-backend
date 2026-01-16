package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"yourapp/internal/i18n"
)

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	sessions, err := s.Sessions.ListForUser(r.Context(), sess.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to fetch sessions")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"sessions": sessions})
}

type deleteSessionRequest struct {
	SessionID string `json:"sessionId"`
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req deleteSessionRequest
	if err := decodeJSON(r, &req); err != nil || req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "sessionId is required")
		return
	}

	target, err := s.Sessions.Get(r.Context(), req.SessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to fetch session")
		return
	}
	if target == nil || target.UserID != sess.UserID {
		writeError(w, http.StatusForbidden, "You can only delete your own sessions.")
		return
	}

	if err := s.Sessions.Delete(r.Context(), req.SessionID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("Session %s deleted.", req.SessionID)})
}

func (s *Server) handleCurrentSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

type updateProfileRequest struct {
	Name  *string `json:"name"`
	Theme *string `json:"theme"`
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req updateProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Theme != nil {
		theme := *req.Theme
		if theme != "light" && theme != "dark" && theme != "system" {
			writeError(w, http.StatusBadRequest, "Invalid theme value")
			return
		}
	}
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		writeError(w, http.StatusBadRequest, "Name cannot be empty")
		return
	}

	user, err := s.Users.UpdateProfile(r.Context(), sess.UserID, req.Name, req.Theme)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update profile")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Profile updated successfully.",
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"theme": user.Theme,
			"role":  user.Role,
		},
	})
}

type updateEmailRequest struct {
	NewEmail string `json:"newEmail"`
}

func (s *Server) handleUpdateEmail(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	locale := i18n.LocaleFromRequest(r)

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}
	if linked, _ := s.Users.HasOAuthAccount(r.Context(), user.ID); linked {
		writeError(w, http.StatusForbidden, "Email cannot be changed for OAuth-linked accounts.")
		return
	}
	needStepUp := user.TwoFactorEnabled
	if !needStepUp {
		if passkeys, _ := s.Users.ListPasskeys(r.Context(), user.ID); len(passkeys) > 0 {
			needStepUp = true
		}
	}
	if needStepUp && !s.requireStepUp(r.Context(), sess, "email_change") {
		if user.TwoFactorMethod != nil && *user.TwoFactorMethod == "email" {
			_ = s.sendTwoFactorEmail(r.Context(), user, locale)
		}
		writeError(w, http.StatusForbidden, "STEP_UP_REQUIRED")
		return
	}

	var req updateEmailRequest
	if err := decodeJSON(r, &req); err != nil || !validateEmail(req.NewEmail) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	existing, err := s.Users.FindByEmail(r.Context(), req.NewEmail)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check email")
		return
	}
	if existing != nil && existing.ID != sess.UserID {
		writeError(w, http.StatusConflict, "This email is already in use by another account.")
		return
	}

	user, err = s.Users.UpdateEmail(r.Context(), sess.UserID, req.NewEmail)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update email")
		return
	}
	_ = s.Users.DeleteVerificationTokens(r.Context(), user.ID)

	if s.Config.NoEmailVerify {
		_ = s.Users.SetEmailVerified(r.Context(), user.ID)
	} else if err := s.issueVerification(r.Context(), user, locale); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to send verification email")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Email updated successfully. Please verify the new address.",
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
		},
	})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req changePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.CurrentPassword == "" {
		writeError(w, http.StatusBadRequest, "Current password is required.")
		return
	}
	if err := validatePassword(req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}
	if linked, _ := s.Users.HasOAuthAccount(r.Context(), user.ID); linked {
		writeError(w, http.StatusForbidden, "Password cannot be changed for OAuth-linked accounts.")
		return
	}
	if user.PasswordHash == nil {
		writeError(w, http.StatusBadRequest, "Password not set for this account.")
		return
	}

	needStepUp := user.TwoFactorEnabled
	if !needStepUp {
		if passkeys, _ := s.Users.ListPasskeys(r.Context(), user.ID); len(passkeys) > 0 {
			needStepUp = true
		}
	}
	if needStepUp && !s.requireStepUp(r.Context(), sess, "password_change") {
		if user.TwoFactorMethod != nil && *user.TwoFactorMethod == "email" {
			locale := i18n.LocaleFromRequest(r)
			_ = s.sendTwoFactorEmail(r.Context(), user, locale)
		}
		writeError(w, http.StatusForbidden, "STEP_UP_REQUIRED")
		return
	}

	if !s.Hasher.Compare(*user.PasswordHash, req.CurrentPassword) {
		writeError(w, http.StatusUnauthorized, "Incorrect current password.")
		return
	}

	hashed, err := s.Hasher.Hash(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	if err := s.Users.UpdatePassword(r.Context(), user.ID, hashed); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to change password")
		return
	}

	_ = s.Sessions.DeleteByUser(r.Context(), user.ID)

	writeJSON(w, http.StatusOK, map[string]string{
		"message":  "Password changed successfully. You will be signed out.",
		"redirect": "/logout",
	})
}

func (s *Server) handleUpdateImage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil { // 5 MB buffer
		writeError(w, http.StatusBadRequest, "Invalid form data")
		return
	}

	file, header, err := r.FormFile("image")
	if err != nil {
		writeError(w, http.StatusBadRequest, "No file uploaded")
		return
	}
	defer file.Close()

	if header.Size > 3*1024*1024 {
		writeError(w, http.StatusBadRequest, "File too large. Max 3MB.")
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read file")
		return
	}

	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}

	validTypes := map[string]bool{
		"image/png":  true,
		"image/jpeg": true,
		"image/jpg":  true,
		"image/webp": true,
	}
	if !validTypes[contentType] {
		writeError(w, http.StatusBadRequest, "Invalid image format.")
		return
	}

	hash := hashBytes(data)
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(header.Filename)), ".")
	if ext == "" {
		switch contentType {
		case "image/png":
			ext = "png"
		case "image/webp":
			ext = "webp"
		default:
			ext = "jpg"
		}
	}

	uploadDir := filepath.Join(s.Config.UploadDir, hash)
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create upload directory")
		return
	}

	filePath := filepath.Join(uploadDir, fmt.Sprintf("profile.%s", ext))
	if err := os.WriteFile(filePath, data, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save image")
		return
	}

	imageURL := fmt.Sprintf("/uploads/%s/profile.%s", hash, ext)

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err == nil && user != nil && user.Image != nil {
		s.removeOldImage(*user.Image)
	}

	if _, err := s.Users.UpdateImage(r.Context(), sess.UserID, imageURL); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update image")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message":  "Uploaded successfully",
		"imageUrl": imageURL,
	})
}

func (s *Server) removeOldImage(imagePath string) {
	if !strings.HasPrefix(imagePath, "/uploads/") {
		return
	}
	rel := strings.TrimPrefix(imagePath, "/uploads/")
	dir := filepath.Dir(rel)
	abs := filepath.Join(s.Config.UploadDir, dir)
	_ = os.RemoveAll(abs)
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}

	needStepUp := user.TwoFactorEnabled
	if !needStepUp {
		if passkeys, _ := s.Users.ListPasskeys(r.Context(), user.ID); len(passkeys) > 0 {
			needStepUp = true
		}
	}
	if needStepUp && !s.requireStepUp(r.Context(), sess, "account_delete") {
		if user.TwoFactorMethod != nil && *user.TwoFactorMethod == "email" {
			locale := i18n.LocaleFromRequest(r)
			_ = s.sendTwoFactorEmail(r.Context(), user, locale)
		}
		writeError(w, http.StatusForbidden, "STEP_UP_REQUIRED")
		return
	}

	if err := s.Users.DeleteUser(r.Context(), sess.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete account")
		return
	}

	_ = s.Sessions.DeleteByUser(r.Context(), sess.UserID)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("Account for %s successfully deleted.", user.Email),
	})
}
