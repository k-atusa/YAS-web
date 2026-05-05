type StepDotsProps = {
	total: number;
	current: number;
};

export const StepDots = ({ total, current }: StepDotsProps) => (
	<div className="step-dots">
		{Array.from({ length: total }, (_, i) => (
			<div
				key={i}
				className={`step-dot ${i + 1 === current ? "active" : i + 1 < current ? "done" : ""}`}
			/>
		))}
	</div>
);
