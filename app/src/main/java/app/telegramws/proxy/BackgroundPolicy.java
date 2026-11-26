package app.telegramws.proxy;

import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;
import android.os.PowerManager;

final class BackgroundPolicy {
    record Status(boolean exempt, boolean restricted, boolean notifications) {
        boolean needsSetup() {
            return !exempt || restricted;
        }
    }

    static Status read(Context context) {
        String name = context.getPackageName();
        boolean exempt = context.getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(name);
        boolean restricted = Build.VERSION.SDK_INT >= 28
            && context.getSystemService(ActivityManager.class).isBackgroundRestricted();
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        var channel = manager.getNotificationChannel(ProxyService.CHANNEL);
        boolean notifications = manager.areNotificationsEnabled()
            && (channel == null || channel.getImportance() != NotificationManager.IMPORTANCE_NONE);
        return new Status(exempt, restricted, notifications);
    }

    static void appendTo(Context context, StringBuilder report) {
        Status status = read(context);
        report.append("\nРабота в фоне\n")
            .append("Исключение из оптимизации батареи: ").append(status.exempt()).append('\n')
            .append("Ограничения фона Android: ")
            .append(Build.VERSION.SDK_INT >= 28 ? Boolean.toString(status.restricted()) : "нет данных").append('\n')
            .append("Уведомление сервиса разрешено: ").append(status.notifications()).append('\n')
            .append("Причина предыдущего завершения процесса по данным Android: ")
            .append(previousExit(context)).append('\n');
    }

    private static String previousExit(Context context) {
        if (Build.VERSION.SDK_INT < 30) {
            return "нет данных";
        }
        try {
            var exits = context.getSystemService(ActivityManager.class)
                .getHistoricalProcessExitReasons(context.getPackageName(), 0, 1);
            if (exits.isEmpty()) {
                return "нет данных";
            }
            return switch (exits.get(0).getReason()) {
                case ApplicationExitInfo.REASON_LOW_MEMORY -> "нехватка памяти";
                case ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "расход ресурсов";
                case ApplicationExitInfo.REASON_USER_REQUESTED -> "остановка по запросу пользователя";
                case ApplicationExitInfo.REASON_USER_STOPPED -> "остановлен профиль Android";
                case ApplicationExitInfo.REASON_PACKAGE_UPDATED -> "обновление приложения";
                case ApplicationExitInfo.REASON_CRASH, ApplicationExitInfo.REASON_CRASH_NATIVE ->
                    "ошибка процесса";
                case ApplicationExitInfo.REASON_ANR -> "приложение не отвечало";
                case ApplicationExitInfo.REASON_SIGNALED -> "процесс завершён сигналом";
                case ApplicationExitInfo.REASON_FREEZER -> "остановка замороженного процесса";
                case ApplicationExitInfo.REASON_PACKAGE_STATE_CHANGE, ApplicationExitInfo.REASON_PERMISSION_CHANGE ->
                    "изменение настроек приложения";
                case ApplicationExitInfo.REASON_INITIALIZATION_FAILURE -> "ошибка запуска процесса";
                case ApplicationExitInfo.REASON_DEPENDENCY_DIED -> "завершился зависимый процесс";
                case ApplicationExitInfo.REASON_EXIT_SELF -> "приложение завершило процесс";
                case ApplicationExitInfo.REASON_UNKNOWN, ApplicationExitInfo.REASON_OTHER -> "нет данных о причине";
                default -> "иная причина";
            };
        } catch (SecurityException ignored) {
            return "нет данных";
        }
    }
}
