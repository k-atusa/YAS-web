import { useEffect, useState } from "react";
import { Toaster as Sonner, type ToasterProps } from "sonner";
import { CircleCheckIcon, InfoIcon, TriangleAlertIcon, OctagonXIcon, Loader2Icon } from "lucide-react";

type ToasterComponentProps = ToasterProps & {
	theme?: "light" | "dark" | "system";
	hasNav?: boolean;
};

// Collision width calculation:
// Centered navigation bar width = 220px (extends from W/2 - 110px to W/2 + 110px).
// Toast width = 22.25rem (356px) with 24px right offset (extends from W - 380px to W - 24px).
// The toast window starts to overlap the navigation bar when W/2 + 110 >= W - 380, i.e. W <= 980px.
// Below or equal to 980px, notifications are placed above the navigation bar to prevent overlap.
const NAV_OVERLAP_BREAKPOINT = 980;

const Toaster = ({
	theme = "system",
	hasNav = true,
	position,
	offset,
	mobileOffset,
	className,
	...props
}: ToasterComponentProps) => {
	const [isDesktop, setIsDesktop] = useState(() => {
		if (typeof window === "undefined") return true;
		return window.innerWidth > NAV_OVERLAP_BREAKPOINT;
	});

	useEffect(() => {
		if (typeof window === "undefined") return;
		const mql = window.matchMedia(`(min-width: ${NAV_OVERLAP_BREAKPOINT + 1}px)`);
		const update = () => {
			setIsDesktop(window.innerWidth > NAV_OVERLAP_BREAKPOINT);
		};

		mql.addEventListener("change", update);
		window.addEventListener("resize", update);
		return () => {
			mql.removeEventListener("change", update);
			window.removeEventListener("resize", update);
		};
	}, []);

	// Desktop (> 980px): bottom-right (24px)
	// Mobile / Overlap range (<= 980px): bottom-center (above nav bar: 86px, or 24px if no nav)
	const resolvedPosition = position ?? (isDesktop ? "bottom-right" : "bottom-center");
	const defaultMobileOffset = hasNav ? "86px" : "24px";
	const resolvedOffset = offset ?? (isDesktop ? "24px" : defaultMobileOffset);
	const resolvedMobileOffset = mobileOffset ?? {
		bottom: defaultMobileOffset,
		left: "16px",
		right: "16px",
		top: "16px",
	};

	return (
		<Sonner
			theme={theme}
			className={`toaster group ${hasNav ? "has-nav" : "no-nav"} ${className ?? ""}`.trim()}
			position={resolvedPosition}
			offset={resolvedOffset}
			mobileOffset={resolvedMobileOffset}
			icons={{
				success: <CircleCheckIcon className="size-4" />,
				info: <InfoIcon className="size-4" />,
				warning: <TriangleAlertIcon className="size-4" />,
				error: <OctagonXIcon className="size-4" />,
				loading: <Loader2Icon className="size-4 animate-spin" />,
			}}
			toastOptions={{
				classNames: {
					toast: "cn-toast",
					title: "text-[0.875rem] leading-tight",
					description: "text-[0.75rem] leading-tight text-muted-foreground",
					icon: "w-[1.125rem] h-[1.125rem]",
				},
			}}
			{...props}
		/>
	);
};

export { Toaster };
