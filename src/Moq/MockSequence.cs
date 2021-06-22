// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD, and Contributors.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using System.ComponentModel;

using Moq.Language;
using Moq.Language.Flow;
using Moq.Protected;

namespace Moq
{
	/// <summary>
	/// Helper class to setup a full trace between many mocks
	/// </summary>
	public class MockSequence
	{
		int sequenceStep;
		int sequenceLength;

		/// <summary>
		/// Initialize a trace setup
		/// </summary>
		public MockSequence()
		{
			sequenceLength = 0;
			sequenceStep = 0;
		}

		/// <summary>
		/// Allow sequence to be repeated
		/// </summary>
		public bool Cyclic { get; set; }

		private void NextStep()
		{
			sequenceStep++;
			if (Cyclic)
				sequenceStep = sequenceStep % sequenceLength;
		}

		internal ISetupConditionResult<TMock> For<TMock>(Mock<TMock> mock)
			where TMock : class
		{
			var expectationPosition = sequenceLength++;

			return new WhenPhrase<TMock>(mock, new Condition(
				condition: () => expectationPosition == sequenceStep,
				success: NextStep));
		}

		internal ISetupConditionResultProtected<TMock,TAnalog> For<TMock,TAnalog>(IProtectedAsMock<TMock, TAnalog> protectedAsMock)
			where TMock : class
			where TAnalog : class
		{
			var expectationPosition = sequenceLength++;

			return new WhenPhraseProtected<TMock, TAnalog>(protectedAsMock, new Condition(
				condition: () => expectationPosition == sequenceStep,
				success: NextStep));
		}

	}

	/// <summary>
	/// Contains extension methods that are related to <see cref="MockSequence"/>.
	/// </summary>
	[EditorBrowsable(EditorBrowsableState.Never)]
	public static class MockSequenceHelper
	{
		/// <summary>
		/// Perform an expectation in the trace.
		/// </summary>
		public static ISetupConditionResult<TMock> InSequence<TMock>(
			this Mock<TMock> mock,
			MockSequence sequence)
			where TMock : class
		{
			Guard.NotNull(sequence, nameof(sequence));

			return sequence.For(mock);
		}

		/// <summary>
		/// Perform an expectation in the trace.
		/// </summary>
		public static ISetupConditionResultProtected<TMock,TAnalog> InSequence<TMock,TAnalog>(
			this IProtectedAsMock<TMock,TAnalog> protectedAsMock,
			MockSequence sequence)
			where TMock : class 
			where TAnalog : class
		{
			Guard.NotNull(sequence, nameof(sequence));

			return sequence.For(protectedAsMock);
		}
	}
}
