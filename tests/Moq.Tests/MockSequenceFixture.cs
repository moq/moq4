// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD, and Contributors.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using Moq.Protected;
using Xunit;

namespace Moq.Tests
{
	public class MockSequenceFixture
	{
		[Fact]
		public void RightSequenceSuccess()
		{
			var a = new Mock<IFoo>(MockBehavior.Strict);
			var b = new Mock<IFoo>(MockBehavior.Strict);

			var sequence = new MockSequence();
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(101);
			b.InSequence(sequence).Setup(x => x.Do(200)).Returns(201);

			a.Object.Do(100);
			b.Object.Do(200);
		}

		[Fact]
		public void InvalidSequenceFail()
		{
			var a = new Mock<IFoo>(MockBehavior.Strict);
			var b = new Mock<IFoo>(MockBehavior.Strict);

			var sequence = new MockSequence();
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(101);
			b.InSequence(sequence).Setup(x => x.Do(200)).Returns(201);

			Assert.Throws<MockException>(() => b.Object.Do(200));
		}

		[Fact]
		public void NoCyclicSequenceFail()
		{
			var a = new Mock<IFoo>(MockBehavior.Strict);
			var b = new Mock<IFoo>(MockBehavior.Strict);

			var sequence = new MockSequence();
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(101);
			b.InSequence(sequence).Setup(x => x.Do(200)).Returns(201);

			Assert.Equal(101, a.Object.Do(100));
			Assert.Equal(201, b.Object.Do(200));

			Assert.Throws<MockException>(() => a.Object.Do(100));
			Assert.Throws<MockException>(() => b.Object.Do(200));
		}

		[Fact]
		public void CyclicSequenceSuccesss()
		{
			var a = new Mock<IFoo>(MockBehavior.Strict);
			var b = new Mock<IFoo>(MockBehavior.Strict);

			var sequence = new MockSequence { Cyclic = true };
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(101);
			b.InSequence(sequence).Setup(x => x.Do(200)).Returns(201);

			Assert.Equal(101, a.Object.Do(100));
			Assert.Equal(201, b.Object.Do(200));

			Assert.Equal(101, a.Object.Do(100));
			Assert.Equal(201, b.Object.Do(200));

			Assert.Equal(101, a.Object.Do(100));
			Assert.Equal(201, b.Object.Do(200));
		}

		[Fact]
		public void SameMockRightSequenceConsecutiveInvocationsWithSameArguments()
		{
			var a = new Mock<IFoo>(MockBehavior.Strict);

			var sequence = new MockSequence();
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(101);
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(102);
			a.InSequence(sequence).Setup(x => x.Do(200)).Returns(201);
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(103);

			Assert.Equal(101, a.Object.Do(100));
			Assert.Equal(102, a.Object.Do(100));
			Assert.Equal(201, a.Object.Do(200));
			Assert.Equal(103, a.Object.Do(100));
		}

		[Fact]
		public void SameMockRightSequenceSuccess()
		{
			var a = new Mock<IFoo>(MockBehavior.Strict);

			var sequence = new MockSequence();
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(101);
			a.InSequence(sequence).Setup(x => x.Do(200)).Returns(201);

			Assert.Equal(101, a.Object.Do(100));
			Assert.Equal(201, a.Object.Do(200));
			Assert.Throws<MockException>(() => a.Object.Do(100));
			Assert.Throws<MockException>(() => a.Object.Do(200));
		}

		[Fact]
		public void SameMockInvalidSequenceFail()
		{
			var a = new Mock<IFoo>(MockBehavior.Strict);

			var sequence = new MockSequence();
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(101);
			a.InSequence(sequence).Setup(x => x.Do(200)).Returns(201);

			Assert.Throws<MockException>(() => a.Object.Do(200));
		}

		[Fact]
		public void WorksWithProtectedAsSuccess()
		{
			var a = new Mock<IFoo>(MockBehavior.Strict);
			var protectedAs = new Mock<Protected>().Protected().As<ProtectedLike>();
			var sequence = new MockSequence();
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(101);
			a.InSequence(sequence).Setup(x => x.Do(200)).Returns(201);
			protectedAs.InSequence(sequence).Setup(y => y.ProtectedDo(300)).Returns(301);

			Assert.Equal(101, a.Object.Do(100));
			Assert.Equal(201, a.Object.Do(200));
			Assert.Equal(301, protectedAs.Mocked.Object.InvokeProtectedDo(300));
			
		}

		[Fact]
		public void WorksWithProtectedAsFailure()
		{
			var a = new Mock<IFoo>(MockBehavior.Strict);
			var protectedAs = new Mock<Protected>().Protected().As<ProtectedLike>();

			var sequence = new MockSequence();
			a.InSequence(sequence).Setup(x => x.Do(100)).Returns(101);
			protectedAs.InSequence(sequence).Setup(y => y.ProtectedDo(300)).Returns(301);
			a.InSequence(sequence).Setup(x => x.Do(200)).Returns(201);

			Assert.Equal(101, a.Object.Do(100));
			Assert.Throws<MockException>(() => a.Object.Do(200));

		}

		public abstract class Protected
		{
			protected abstract int ProtectedDo(int arg);
			public int InvokeProtectedDo(int arg)
			{
				return ProtectedDo(arg);
			}
		}

		public interface ProtectedLike
		{
			int ProtectedDo(int arg);
		}

		public interface IFoo
		{
			int Do(int arg);
		}
	}
}
